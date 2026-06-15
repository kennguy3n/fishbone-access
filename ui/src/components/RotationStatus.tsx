import { useMemo, useState, type ReactNode } from "react";
import { useIntl } from "react-intl";
import {
  Badge,
  Card,
  Stat,
  StatusBadge,
  AsyncBoundary,
} from "@/components/ui";
import { DataTable, type Column } from "@/components/DataTable";
import { EmptyState } from "@/components/EmptyState";
import { Modal } from "@/components/Modal";
import { HelpTooltip } from "@/components/HelpTooltip";
import { useToast } from "@/components/Toast";
import {
  ApiError,
  MIN_ROTATION_INTERVAL_SECONDS,
  useRotationStatus,
  useUpsertRotationPolicy,
  useDeleteRotationPolicy,
  useRotateTargetNow,
  type RotationEvent,
  type RotationPolicy,
  type RotationPolicyInput,
  type DynamicCredential,
} from "@/api/access";
import { formatDateTime, formatRelative, titleCase } from "@/lib/format";

// Protocols the rotation engine has real executors for (SSH key/password,
// Postgres/MySQL ALTER USER). Dynamic ephemeral credentials are database-only.
const DYNAMIC_PROTOCOLS = new Set(["postgres", "mysql"]);

type IntervalUnit = "hours" | "days";

interface DraftPolicy {
  enabled: boolean;
  interval: boolean;
  intervalValue: number;
  intervalUnit: IntervalUnit;
  rotateOnCheckin: boolean;
  dynamicEnabled: boolean;
  dynamicTtlMinutes: number;
}

const UNIT_SECONDS: Record<IntervalUnit, number> = {
  hours: 3600,
  days: 86400,
};

// Pick the largest whole unit so 86400s reads as "1 day", 7200s as "2 hours".
function secondsToInterval(seconds: number): {
  value: number;
  unit: IntervalUnit;
} {
  if (seconds > 0 && seconds % UNIT_SECONDS.days === 0) {
    return { value: seconds / UNIT_SECONDS.days, unit: "days" };
  }
  const hours = Math.max(1, Math.round(seconds / UNIT_SECONDS.hours));
  return { value: hours, unit: "hours" };
}

function draftFromPolicy(policy: RotationPolicy | null): DraftPolicy {
  if (!policy) {
    return {
      enabled: true,
      interval: false,
      intervalValue: 30,
      intervalUnit: "days",
      rotateOnCheckin: false,
      dynamicEnabled: false,
      dynamicTtlMinutes: 60,
    };
  }
  const iv = secondsToInterval(policy.interval_seconds || 30 * UNIT_SECONDS.days);
  return {
    enabled: policy.enabled,
    interval: policy.mode === "interval",
    intervalValue: iv.value,
    intervalUnit: iv.unit,
    rotateOnCheckin: policy.rotate_on_checkin,
    dynamicEnabled: policy.dynamic_enabled,
    dynamicTtlMinutes: policy.dynamic_ttl_seconds
      ? Math.max(1, Math.round(policy.dynamic_ttl_seconds / 60))
      : 60,
  };
}

function draftToInput(d: DraftPolicy): RotationPolicyInput {
  const intervalSeconds = d.interval
    ? d.intervalValue * UNIT_SECONDS[d.intervalUnit]
    : 0;
  return {
    mode: d.interval ? "interval" : "disabled",
    interval_seconds: intervalSeconds,
    rotate_on_checkin: d.rotateOnCheckin,
    dynamic_enabled: d.dynamicEnabled,
    dynamic_ttl_seconds: d.dynamicEnabled ? d.dynamicTtlMinutes * 60 : 0,
    enabled: d.enabled,
  };
}

/**
 * RotationStatus is the per-target credential-rotation panel: it shows whether
 * and how a target rotates (mode, last/next rotation, last outcome), the
 * rotation history, and any live ephemeral database credentials, and lets an
 * operator edit the policy, trigger an immediate rotation, or turn rotation
 * off. It is self-contained (fetches its own status) so it can be embedded on
 * the Rotation console and reused elsewhere on the PAM surface.
 */
export function RotationStatus({
  targetId,
  targetName,
  protocol,
}: {
  targetId: string;
  targetName: string;
  protocol: string;
}) {
  const intl = useIntl();
  const toast = useToast();
  const { data, isLoading, error, refetch } = useRotationStatus(targetId);
  const upsertMut = useUpsertRotationPolicy(targetId);
  const deleteMut = useDeleteRotationPolicy(targetId);
  const rotateMut = useRotateTargetNow(targetId);

  const [editing, setEditing] = useState(false);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [confirmDisable, setConfirmDisable] = useState(false);
  const [draft, setDraft] = useState<DraftPolicy>(() => draftFromPolicy(null));

  const supportsDynamic = DYNAMIC_PROTOCOLS.has(protocol);

  const openEditor = (policy: RotationPolicy | null) => {
    setDraft(draftFromPolicy(policy));
    setEditing(true);
  };

  const intervalTooSmall =
    draft.interval &&
    draft.intervalValue * UNIT_SECONDS[draft.intervalUnit] <
      MIN_ROTATION_INTERVAL_SECONDS;

  const saveDisabled = upsertMut.isPending || intervalTooSmall;

  const save = async () => {
    if (saveDisabled) return;
    try {
      await upsertMut.mutateAsync(draftToInput(draft));
      toast.success(
        intl.formatMessage({
          id: "rotation.toast.saved",
          defaultMessage: "Rotation policy saved",
        }),
      );
      setEditing(false);
      refetch();
    } catch (err) {
      toast.error(
        intl.formatMessage({
          id: "rotation.toast.saveFailed",
          defaultMessage: "Could not save rotation policy",
        }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  const rotateNow = async () => {
    try {
      const event = await rotateMut.mutateAsync();
      if (event.status === "success") {
        toast.success(
          intl.formatMessage({
            id: "rotation.toast.rotated",
            defaultMessage: "Credential rotated and re-sealed",
          }),
        );
      } else {
        toast.error(
          intl.formatMessage({
            id: "rotation.toast.rotateFailedEvent",
            defaultMessage: "Rotation failed",
          }),
          event.error,
        );
      }
      setConfirmRotate(false);
      refetch();
    } catch (err) {
      toast.error(
        intl.formatMessage({
          id: "rotation.toast.rotateFailed",
          defaultMessage: "Could not rotate credential",
        }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  const disableRotation = async () => {
    try {
      await deleteMut.mutateAsync();
      toast.success(
        intl.formatMessage({
          id: "rotation.toast.disabled",
          defaultMessage: "Automatic rotation turned off",
        }),
      );
      setConfirmDisable(false);
      refetch();
    } catch (err) {
      toast.error(
        intl.formatMessage({
          id: "rotation.toast.disableFailed",
          defaultMessage: "Could not turn off rotation",
        }),
        err instanceof ApiError ? err.message : undefined,
      );
    }
  };

  return (
    <AsyncBoundary
      isLoading={isLoading}
      error={error}
      data={data}
      onRetry={refetch}
    >
      {(status) => {
        const policy = status.policy;
        const rotatable = status.rotatable;
        return (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            {!rotatable && (
              <div className="callout callout--info" role="note">
                {intl.formatMessage(
                  {
                    id: "rotation.unsupported",
                    defaultMessage:
                      "Automatic rotation isn't available for {protocol} targets. ShieldNet can rotate SSH, PostgreSQL and MySQL credentials today; you can still rotate other targets manually from the vault.",
                  },
                  { protocol },
                )}
              </div>
            )}

            <SummaryCards policy={policy} intl={intl} />

            {policy?.last_status === "failed" && policy.last_error && (
              <div
                className="callout"
                role="alert"
                style={{
                  borderColor: "var(--danger)",
                  color: "var(--danger)",
                  background: "var(--danger-soft, rgba(192,57,43,0.08))",
                }}
              >
                <b>
                  {intl.formatMessage({
                    id: "rotation.lastError",
                    defaultMessage: "Last rotation failed",
                  })}
                  :
                </b>{" "}
                {policy.last_error}
              </div>
            )}

            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button
                className="btn btn--primary"
                disabled={!rotatable}
                onClick={() => setConfirmRotate(true)}
              >
                {intl.formatMessage({
                  id: "rotation.action.rotateNow",
                  defaultMessage: "Rotate now",
                })}
              </button>
              <button
                className="btn"
                disabled={!rotatable}
                onClick={() => openEditor(policy)}
              >
                {policy
                  ? intl.formatMessage({
                      id: "rotation.action.edit",
                      defaultMessage: "Edit policy",
                    })
                  : intl.formatMessage({
                      id: "rotation.action.configure",
                      defaultMessage: "Configure rotation",
                    })}
              </button>
              {policy && (
                <button
                  className="btn btn--ghost btn--danger"
                  onClick={() => setConfirmDisable(true)}
                >
                  {intl.formatMessage({
                    id: "rotation.action.disable",
                    defaultMessage: "Turn off",
                  })}
                </button>
              )}
            </div>

            <HistoryCard events={status.events} intl={intl} />

            {(supportsDynamic || status.dynamic_credentials.length > 0) && (
              <DynamicCard
                creds={status.dynamic_credentials}
                enabled={!!policy?.dynamic_enabled}
                intl={intl}
              />
            )}

            {editing && (
              <PolicyEditorModal
                targetName={targetName}
                protocol={protocol}
                supportsDynamic={supportsDynamic}
                draft={draft}
                setDraft={setDraft}
                intervalTooSmall={!!intervalTooSmall}
                saving={upsertMut.isPending}
                saveDisabled={saveDisabled}
                onCancel={() => setEditing(false)}
                onSave={save}
                intl={intl}
              />
            )}

            {confirmRotate && (
              <Modal
                title={intl.formatMessage({
                  id: "rotation.confirm.rotateTitle",
                  defaultMessage: "Rotate this credential now?",
                })}
                onClose={() => setConfirmRotate(false)}
                footer={
                  <>
                    <button
                      className="btn btn--ghost"
                      onClick={() => setConfirmRotate(false)}
                    >
                      {intl.formatMessage({
                        id: "common.cancel",
                        defaultMessage: "Cancel",
                      })}
                    </button>
                    <button
                      className="btn btn--primary"
                      disabled={rotateMut.isPending}
                      onClick={rotateNow}
                    >
                      {intl.formatMessage({
                        id: "rotation.confirm.rotateConfirm",
                        defaultMessage: "Rotate now",
                      })}
                    </button>
                  </>
                }
              >
                <p>
                  {intl.formatMessage(
                    {
                      id: "rotation.confirm.rotateBody",
                      defaultMessage:
                        "ShieldNet will generate a fresh credential on {name}, verify it, and re-seal it in the vault. The current credential stops working immediately. Live sessions are unaffected.",
                    },
                    { name: targetName },
                  )}
                </p>
              </Modal>
            )}

            {confirmDisable && (
              <Modal
                title={intl.formatMessage({
                  id: "rotation.confirm.disableTitle",
                  defaultMessage: "Turn off automatic rotation?",
                })}
                onClose={() => setConfirmDisable(false)}
                footer={
                  <>
                    <button
                      className="btn btn--ghost"
                      onClick={() => setConfirmDisable(false)}
                    >
                      {intl.formatMessage({
                        id: "common.cancel",
                        defaultMessage: "Cancel",
                      })}
                    </button>
                    <button
                      className="btn btn--danger"
                      disabled={deleteMut.isPending}
                      onClick={disableRotation}
                    >
                      {intl.formatMessage({
                        id: "rotation.confirm.disableConfirm",
                        defaultMessage: "Turn off rotation",
                      })}
                    </button>
                  </>
                }
              >
                <p>
                  {intl.formatMessage({
                    id: "rotation.confirm.disableBody",
                    defaultMessage:
                      "Scheduled and on-checkin rotation will stop and ephemeral credentials will no longer be issued. The credential currently in the vault keeps working — this only stops future automatic changes. You can re-enable rotation at any time.",
                  })}
                </p>
              </Modal>
            )}
          </div>
        );
      }}
    </AsyncBoundary>
  );
}

type Intl = ReturnType<typeof useIntl>;

function modeSummary(policy: RotationPolicy | null, intl: Intl): string {
  if (!policy || (!policy.enabled && policy.mode === "disabled")) {
    return intl.formatMessage({
      id: "rotation.mode.manual",
      defaultMessage: "Manual only",
    });
  }
  const parts: string[] = [];
  if (policy.mode === "interval" && policy.interval_seconds > 0) {
    const iv = secondsToInterval(policy.interval_seconds);
    parts.push(
      iv.unit === "days"
        ? intl.formatMessage(
            { id: "rotation.mode.everyDays", defaultMessage: "Every {n, plural, one {# day} other {# days}}" },
            { n: iv.value },
          )
        : intl.formatMessage(
            { id: "rotation.mode.everyHours", defaultMessage: "Every {n, plural, one {# hour} other {# hours}}" },
            { n: iv.value },
          ),
    );
  }
  if (policy.rotate_on_checkin) {
    parts.push(
      intl.formatMessage({
        id: "rotation.mode.onCheckin",
        defaultMessage: "On check-in",
      }),
    );
  }
  if (parts.length === 0) {
    return intl.formatMessage({
      id: "rotation.mode.manual",
      defaultMessage: "Manual only",
    });
  }
  return parts.join(" · ");
}

function SummaryCards({
  policy,
  intl,
}: {
  policy: RotationPolicy | null;
  intl: Intl;
}) {
  return (
    <div className="grid grid--stats">
      <Stat
        label={intl.formatMessage({
          id: "rotation.stat.status",
          defaultMessage: "Status",
        })}
        value={
          policy?.last_status ? (
            <StatusBadge status={policy.last_status} />
          ) : (
            <Badge tone="neutral">
              {intl.formatMessage({
                id: "rotation.never",
                defaultMessage: "Never rotated",
              })}
            </Badge>
          )
        }
      />
      <Stat
        label={intl.formatMessage({
          id: "rotation.stat.mode",
          defaultMessage: "Schedule",
        })}
        value={modeSummary(policy, intl)}
      />
      <Stat
        label={intl.formatMessage({
          id: "rotation.stat.lastRotated",
          defaultMessage: "Last rotated",
        })}
        value={formatRelative(policy?.last_rotation_at)}
      />
      <Stat
        label={intl.formatMessage({
          id: "rotation.stat.nextRotation",
          defaultMessage: "Next rotation",
        })}
        value={
          policy?.next_rotation_at
            ? formatRelative(policy.next_rotation_at)
            : "—"
        }
      />
      <Stat
        label={intl.formatMessage({
          id: "rotation.stat.dynamic",
          defaultMessage: "Ephemeral credentials",
        })}
        value={
          policy?.dynamic_enabled ? (
            <Badge tone="info">
              {intl.formatMessage(
                {
                  id: "rotation.dynamic.enabledTtl",
                  defaultMessage: "On · {n}m TTL",
                },
                { n: Math.max(1, Math.round((policy.dynamic_ttl_seconds || 0) / 60)) },
              )}
            </Badge>
          ) : (
            <Badge tone="neutral">
              {intl.formatMessage({
                id: "rotation.dynamic.off",
                defaultMessage: "Off",
              })}
            </Badge>
          )
        }
      />
    </div>
  );
}

function triggerTone(trigger: string): "info" | "warn" | "neutral" {
  switch (trigger) {
    case "manual":
      return "warn";
    case "checkin":
      return "info";
    default:
      return "neutral";
  }
}

function HistoryCard({ events, intl }: { events: RotationEvent[]; intl: Intl }) {
  const columns: Column<RotationEvent>[] = useMemo(
    () => [
      {
        header: intl.formatMessage({
          id: "rotation.col.when",
          defaultMessage: "When",
        }),
        cell: (e) => (
          <span title={formatDateTime(e.created_at)}>
            {formatRelative(e.created_at)}
          </span>
        ),
      },
      {
        header: intl.formatMessage({
          id: "rotation.col.trigger",
          defaultMessage: "Trigger",
        }),
        cell: (e) => <Badge tone={triggerTone(e.trigger)}>{titleCase(e.trigger)}</Badge>,
      },
      {
        header: intl.formatMessage({
          id: "rotation.col.outcome",
          defaultMessage: "Outcome",
        }),
        cell: (e) => <StatusBadge status={e.status} />,
      },
      {
        header: intl.formatMessage({
          id: "rotation.col.actor",
          defaultMessage: "Actor",
        }),
        cell: (e) => <span className="muted">{e.actor || "—"}</span>,
      },
      {
        header: intl.formatMessage({
          id: "rotation.col.detail",
          defaultMessage: "Detail",
        }),
        cell: (e) =>
          e.status === "failed" ? (
            <span className="muted" style={{ color: "var(--danger, #c0392b)" }}>
              {e.error || "—"}
            </span>
          ) : (
            <span className="muted">{e.detail || "—"}</span>
          ),
      },
    ],
    [intl],
  );

  return (
    <Card
      title={intl.formatMessage({
        id: "rotation.history.title",
        defaultMessage: "Rotation history",
      })}
      subtitle={intl.formatMessage({
        id: "rotation.history.subtitle",
        defaultMessage:
          "Every rotation attempt is also written to the tamper-evident audit chain.",
      })}
    >
      {events.length === 0 ? (
        <EmptyState
          title={intl.formatMessage({
            id: "rotation.history.emptyTitle",
            defaultMessage: "No rotations yet",
          })}
          description={intl.formatMessage({
            id: "rotation.history.emptyBody",
            defaultMessage:
              "Once this credential rotates — on a schedule, after a check-in, or on demand — each attempt shows here.",
          })}
        />
      ) : (
        <DataTable
          columns={columns}
          rows={events}
          rowKey={(e) => e.id}
        />
      )}
    </Card>
  );
}

function dynamicStateTone(state: string): "ok" | "warn" | "danger" | "neutral" {
  switch (state) {
    case "active":
      return "ok";
    case "expired":
    case "revoked":
      return "neutral";
    case "failed":
      return "danger";
    default:
      return "neutral";
  }
}

function DynamicCard({
  creds,
  enabled,
  intl,
}: {
  creds: DynamicCredential[];
  enabled: boolean;
  intl: Intl;
}) {
  const columns: Column<DynamicCredential>[] = useMemo(
    () => [
      {
        header: intl.formatMessage({
          id: "rotation.dyn.col.user",
          defaultMessage: "Database user",
        }),
        cell: (c) => <code>{c.db_username}</code>,
      },
      {
        header: intl.formatMessage({
          id: "rotation.dyn.col.state",
          defaultMessage: "State",
        }),
        cell: (c) => <Badge tone={dynamicStateTone(c.state)}>{titleCase(c.state)}</Badge>,
      },
      {
        header: intl.formatMessage({
          id: "rotation.dyn.col.expires",
          defaultMessage: "Expires",
        }),
        cell: (c) => (
          <span title={formatDateTime(c.expires_at)}>
            {formatRelative(c.expires_at)}
          </span>
        ),
      },
    ],
    [intl],
  );

  return (
    <Card
      title={intl.formatMessage({
        id: "rotation.dyn.title",
        defaultMessage: "Ephemeral credentials",
      })}
      actions={
        <HelpTooltip
          align="right"
          title={intl.formatMessage({
            id: "rotation.dyn.help.title",
            defaultMessage: "What are ephemeral credentials?",
          })}
        >
          {intl.formatMessage({
            id: "rotation.dyn.help.body",
            defaultMessage:
              "Instead of handing out one long-lived database password, ShieldNet can mint a unique short-lived database user for each approved lease and drop it automatically when the lease ends — so there's no standing credential to steal.",
          })}
        </HelpTooltip>
      }
    >
      {creds.length === 0 ? (
        <EmptyState
          title={
            enabled
              ? intl.formatMessage({
                  id: "rotation.dyn.emptyOnTitle",
                  defaultMessage: "No live ephemeral credentials",
                })
              : intl.formatMessage({
                  id: "rotation.dyn.emptyOffTitle",
                  defaultMessage: "Ephemeral credentials are off",
                })
          }
          description={
            enabled
              ? intl.formatMessage({
                  id: "rotation.dyn.emptyOnBody",
                  defaultMessage:
                    "A short-lived database user is minted per approved lease and shown here while it is live.",
                })
              : intl.formatMessage({
                  id: "rotation.dyn.emptyOffBody",
                  defaultMessage:
                    "Turn on ephemeral credentials in the rotation policy to issue a unique, auto-expiring database user for each lease.",
                })
          }
        />
      ) : (
        <DataTable columns={columns} rows={creds} rowKey={(c) => c.id} />
      )}
    </Card>
  );
}

function ToggleRow({
  checked,
  onChange,
  disabled,
  title,
  hint,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  title: string;
  hint?: ReactNode;
}) {
  return (
    <label
      style={{
        display: "flex",
        gap: 10,
        alignItems: "flex-start",
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled ? 0.55 : 1,
      }}
    >
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        style={{ marginTop: 3 }}
      />
      <span>
        <b>{title}</b>
        {hint != null && (
          <span className="muted" style={{ display: "block", fontSize: 12 }}>
            {hint}
          </span>
        )}
      </span>
    </label>
  );
}

function PolicyEditorModal({
  targetName,
  protocol,
  supportsDynamic,
  draft,
  setDraft,
  intervalTooSmall,
  saving,
  saveDisabled,
  onCancel,
  onSave,
  intl,
}: {
  targetName: string;
  protocol: string;
  supportsDynamic: boolean;
  draft: DraftPolicy;
  setDraft: (d: DraftPolicy) => void;
  intervalTooSmall: boolean;
  saving: boolean;
  saveDisabled: boolean;
  onCancel: () => void;
  onSave: () => void;
  intl: Intl;
}) {
  const set = <K extends keyof DraftPolicy>(key: K, value: DraftPolicy[K]) =>
    setDraft({ ...draft, [key]: value });

  return (
    <Modal
      title={intl.formatMessage(
        {
          id: "rotation.editor.title",
          defaultMessage: "Rotation policy — {name}",
        },
        { name: targetName },
      )}
      onClose={onCancel}
      footer={
        <>
          <button className="btn btn--ghost" onClick={onCancel}>
            {intl.formatMessage({ id: "common.cancel", defaultMessage: "Cancel" })}
          </button>
          <button
            className="btn btn--primary"
            disabled={saveDisabled}
            onClick={onSave}
          >
            {saving
              ? intl.formatMessage({
                  id: "rotation.editor.saving",
                  defaultMessage: "Saving…",
                })
              : intl.formatMessage({
                  id: "rotation.editor.save",
                  defaultMessage: "Save policy",
                })}
          </button>
        </>
      }
    >
      <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
        <ToggleRow
          checked={draft.enabled}
          onChange={(v) => set("enabled", v)}
          title={intl.formatMessage({
            id: "rotation.editor.enabled",
            defaultMessage: "Rotation enabled",
          })}
          hint={intl.formatMessage({
            id: "rotation.editor.enabledHint",
            defaultMessage:
              "Master switch. Turn off to pause all automatic rotation without losing your settings.",
          })}
        />

        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <span
            className="field__label"
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
              marginBottom: 0,
            }}
          >
            {intl.formatMessage({
              id: "rotation.editor.schedule",
              defaultMessage: "Rotate on a schedule",
            })}
            <HelpTooltip>
              {intl.formatMessage({
                id: "rotation.editor.scheduleHelp",
                defaultMessage:
                  "Automatically change this credential every set period — a common compliance requirement (e.g. every 30 or 90 days).",
              })}
            </HelpTooltip>
          </span>
          <ToggleRow
            checked={draft.interval}
            onChange={(v) => set("interval", v)}
            title={intl.formatMessage({
              id: "rotation.editor.scheduleToggle",
              defaultMessage: "Rotate automatically on a fixed interval",
            })}
          />
          {draft.interval && (
            <div className="field-row" style={{ marginTop: 4 }}>
              <label className="field" style={{ maxWidth: 140 }}>
                <span>
                  {intl.formatMessage({
                    id: "rotation.editor.every",
                    defaultMessage: "Rotate every",
                  })}
                </span>
                <input
                  type="number"
                  min={1}
                  value={draft.intervalValue}
                  onChange={(e) =>
                    set("intervalValue", Math.max(1, Number(e.target.value) || 1))
                  }
                />
              </label>
              <label className="field" style={{ maxWidth: 140 }}>
                <span>
                  {intl.formatMessage({
                    id: "rotation.editor.unit",
                    defaultMessage: "Unit",
                  })}
                </span>
                <select
                  value={draft.intervalUnit}
                  onChange={(e) =>
                    set("intervalUnit", e.target.value as IntervalUnit)
                  }
                >
                  <option value="hours">
                    {intl.formatMessage({
                      id: "rotation.editor.hours",
                      defaultMessage: "Hours",
                    })}
                  </option>
                  <option value="days">
                    {intl.formatMessage({
                      id: "rotation.editor.days",
                      defaultMessage: "Days",
                    })}
                  </option>
                </select>
              </label>
            </div>
          )}
          {intervalTooSmall && (
            <p className="form-error">
              {intl.formatMessage({
                id: "rotation.editor.intervalFloor",
                defaultMessage: "The shortest allowed interval is 1 hour.",
              })}
            </p>
          )}
        </div>

        <ToggleRow
          checked={draft.rotateOnCheckin}
          onChange={(v) => set("rotateOnCheckin", v)}
          title={intl.formatMessage({
            id: "rotation.editor.checkin",
            defaultMessage: "Rotate after each use (check-in)",
          })}
          hint={intl.formatMessage({
            id: "rotation.editor.checkinHint",
            defaultMessage:
              "When a just-in-time access lease ends, rotate the credential so it can never be reused after the session.",
          })}
        />

        <ToggleRow
          checked={draft.dynamicEnabled}
          disabled={!supportsDynamic}
          onChange={(v) => set("dynamicEnabled", v)}
          title={intl.formatMessage({
            id: "rotation.editor.dynamic",
            defaultMessage: "Issue ephemeral credentials",
          })}
          hint={
            supportsDynamic
              ? intl.formatMessage({
                  id: "rotation.editor.dynamicHint",
                  defaultMessage:
                    "Mint a unique, short-lived database user for each lease instead of sharing one stored password. Dropped automatically when the lease ends.",
                })
              : intl.formatMessage(
                  {
                    id: "rotation.editor.dynamicUnsupported",
                    defaultMessage:
                      "Ephemeral credentials are available for PostgreSQL and MySQL targets only (this is a {protocol} target).",
                  },
                  { protocol },
                )
          }
        />

        {draft.dynamicEnabled && supportsDynamic && (
          <label className="field" style={{ maxWidth: 220 }}>
            <span>
              {intl.formatMessage({
                id: "rotation.editor.ttl",
                defaultMessage: "Credential lifetime (minutes)",
              })}
            </span>
            <input
              type="number"
              min={1}
              value={draft.dynamicTtlMinutes}
              onChange={(e) =>
                set("dynamicTtlMinutes", Math.max(1, Number(e.target.value) || 1))
              }
            />
          </label>
        )}
      </div>
    </Modal>
  );
}
