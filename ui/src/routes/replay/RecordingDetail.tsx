import { useMemo } from "react";
import { FormattedMessage, useIntl } from "react-intl";
import { useNavigate, useParams } from "@tanstack/react-router";
import {
  PageHeader,
  Card,
  Stat,
  Badge,
  StatusBadge,
  LoadingState,
  ErrorState,
} from "@/components/ui";
import { EmptyState } from "@/components/EmptyState";
import { ApiError } from "@/api/access";
import { formatDateTime } from "@/lib/format";
import {
  useRecording,
  useRecordingFrames,
  type CommandTimelineEntry,
} from "./api";
import { usePlayback } from "./usePlayback";
import { ReplayPlayer } from "./ReplayPlayer";
import { CommandTimeline } from "./CommandTimeline";
import { TamperBadge } from "./TamperBadge";
import { computeCommandOffsets, formatBytes, formatDurationMs } from "./util";

// RecordingDetail is the flagship session-replay player: a recording's
// metadata, the live tamper verdict, the terminal-style transcript with
// transport controls, and a synchronized command timeline. Metadata + timeline
// come from the light indexed row (instant); the heavy frame bytes are streamed
// separately so the page paints immediately and only fetches the transcript
// when present. When the blob has been tiered out by retention (409), the
// metadata and command timeline remain fully available.
export function RecordingDetail() {
  const intl = useIntl();
  const navigate = useNavigate();
  const { recordingId } = useParams({ strict: false }) as {
    recordingId?: string;
  };

  const detailQ = useRecording(recordingId);
  const framesQ = useRecordingFrames(recordingId, { retry: false });

  const frames = useMemo(
    () => framesQ.data?.frames ?? [],
    [framesQ.data],
  );
  const playback = usePlayback(frames);

  const timeline: CommandTimelineEntry[] = useMemo(
    () => detailQ.data?.timeline ?? [],
    [detailQ.data],
  );
  const commandOffsets = useMemo(
    () =>
      computeCommandOffsets(
        frames,
        playback.offsets,
        timeline.map((t) => t.command),
      ),
    [frames, playback.offsets, timeline],
  );

  const blobUnavailable =
    framesQ.error instanceof ApiError && framesQ.error.status === 409;

  return (
    <>
      <PageHeader
        title={intl.formatMessage({ id: "replay.detail.1", defaultMessage: "Session replay" })}
        subtitle={intl.formatMessage({ id: "replay.detail.2",
          defaultMessage:
            "Watch the time-ordered transcript with a synchronized command timeline and a verified tamper badge.",
        })}
        actions={
          <button
            className="btn btn--ghost"
            onClick={() => navigate({ to: "/pam/recordings" })}
          >
            <FormattedMessage id="replay.detail.23" defaultMessage="Back to search" />
          </button>
        }
      />

      {detailQ.isLoading ? (
        <LoadingState />
      ) : detailQ.error ? (
        <ErrorState error={detailQ.error} onRetry={() => detailQ.refetch()} />
      ) : !detailQ.data ? (
        <EmptyState
          title={intl.formatMessage({ id: "replay.detail.3", defaultMessage: "Recording not found" })}
        />
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
          {(() => {
            const r = detailQ.data.recording;
            const tamper = framesQ.data;
            return (
              <>
                <Card
                  title={`${r.operator || intl.formatMessage({ id: "replay.detail.4", defaultMessage: "Unknown operator" })} · ${r.target_name || intl.formatMessage({ id: "replay.detail.5", defaultMessage: "Unknown target" })}`}
                  subtitle={intl.formatMessage({ id: "replay.detail.6",
                    defaultMessage: "Recorded privileged session",
                  })}
                  actions={
                    tamper ? (
                      <TamperBadge
                        anchored={tamper.anchored}
                        verified={tamper.verified}
                      />
                    ) : r.sha256 ? (
                      <Badge tone="neutral">
                        <FormattedMessage id="replay.detail.24" defaultMessage="Integrity: checking…" />
                      </Badge>
                    ) : null
                  }
                >
                  <div
                    style={{
                      display: "grid",
                      gridTemplateColumns:
                        "repeat(auto-fit, minmax(150px, 1fr))",
                      gap: 12,
                    }}
                  >
                    <Stat
                      label={intl.formatMessage({ id: "replay.detail.7", defaultMessage: "Protocol" })}
                      value={<Badge tone="info">{r.protocol || "—"}</Badge>}
                    />
                    <Stat
                      label={intl.formatMessage({ id: "replay.detail.8", defaultMessage: "State" })}
                      value={<StatusBadge status={r.state} />}
                    />
                    <Stat
                      label={intl.formatMessage({ id: "replay.detail.9", defaultMessage: "Started" })}
                      value={
                        <span style={{ fontSize: 14 }}>
                          {formatDateTime(r.started_at)}
                        </span>
                      }
                    />
                    <Stat
                      label={intl.formatMessage({ id: "replay.detail.10", defaultMessage: "Duration" })}
                      value={formatDurationMs(r.duration_ms)}
                    />
                    <Stat
                      label={intl.formatMessage({ id: "replay.detail.11", defaultMessage: "Commands" })}
                      value={r.command_count}
                    />
                    <Stat
                      label={intl.formatMessage({ id: "replay.detail.12",
                        defaultMessage: "Policy denies",
                      })}
                      value={
                        r.deny_count > 0 ? (
                          <span style={{ color: "var(--danger)" }}>
                            {r.deny_count}
                          </span>
                        ) : (
                          0
                        )
                      }
                    />
                    <Stat
                      label={intl.formatMessage({ id: "replay.detail.13", defaultMessage: "Size" })}
                      value={formatBytes(r.bytes)}
                    />
                    <Stat
                      label={intl.formatMessage({ id: "replay.detail.14", defaultMessage: "Client" })}
                      value={
                        <span style={{ fontSize: 14 }}>
                          {r.client_addr || "—"}
                        </span>
                      }
                    />
                  </div>
                  {r.truncated && (
                    <p className="muted" style={{ marginTop: 12 }}>
                      <Badge tone="warn">
                        <FormattedMessage id="replay.detail.25" defaultMessage="Truncated" />
                      </Badge>{" "}
                      <FormattedMessage id="replay.detail.26" defaultMessage="The gateway size cap dropped trailing payload from this recording." />
                    </p>
                  )}
                </Card>

                <div
                  className="replay-layout"
                  style={{
                    display: "grid",
                    gridTemplateColumns: "minmax(0, 2fr) minmax(260px, 1fr)",
                    gap: 16,
                    alignItems: "start",
                  }}
                >
                  <Card title={intl.formatMessage({ id: "replay.detail.15", defaultMessage: "Replay" })}>
                    {framesQ.isLoading ? (
                      <LoadingState
                        label={intl.formatMessage({ id: "replay.detail.16",
                          defaultMessage: "Loading transcript…",
                        })}
                      />
                    ) : blobUnavailable || r.blob_pruned ? (
                      <EmptyState
                        title={intl.formatMessage({ id: "replay.detail.17",
                          defaultMessage: "Replay tiered out",
                        })}
                        description={intl.formatMessage({ id: "replay.detail.18",
                          defaultMessage:
                            "This recording's bytes were removed by the retention policy to control storage cost. Its searchable metadata, command timeline, and audit-chain integrity record are preserved.",
                        })}
                      />
                    ) : framesQ.error ? (
                      <ErrorState
                        error={framesQ.error}
                        onRetry={() => framesQ.refetch()}
                      />
                    ) : frames.length === 0 ? (
                      <EmptyState
                        title={intl.formatMessage({ id: "replay.detail.19",
                          defaultMessage: "No transcript",
                        })}
                        description={intl.formatMessage({ id: "replay.detail.20",
                          defaultMessage:
                            "This recording contains no replayable frames.",
                        })}
                      />
                    ) : (
                      <ReplayPlayer frames={frames} playback={playback} />
                    )}
                  </Card>

                  <Card
                    title={intl.formatMessage({ id: "replay.detail.21",
                      defaultMessage: "Command timeline",
                    })}
                    subtitle={intl.formatMessage({ id: "replay.detail.22",
                      defaultMessage:
                        "Click a command to jump to it. Denied commands are highlighted.",
                    })}
                  >
                    <CommandTimeline
                      timeline={timeline}
                      offsetsMs={commandOffsets}
                      posMs={playback.posMs}
                      onJump={(_, i) => {
                        const off = commandOffsets[i];
                        if (off != null) {
                          playback.seekMs(off);
                          playback.pause();
                        }
                      }}
                    />
                  </Card>
                </div>
              </>
            );
          })()}
        </div>
      )}
    </>
  );
}
