import { useMemo, useState } from "react";
import { useNavigate, useParams } from "@tanstack/react-router";
import {
  PageHeader,
  Card,
  Badge,
  AsyncBoundary,
} from "@/components/ui";
import { Modal } from "@/components/Modal";
import { useToast } from "@/components/Toast";
import { usePack, useApplyPack, type PackTemplate } from "@/api/access";

export function PackDetail() {
  const params = useParams({ strict: false }) as { packId?: string };
  const packId = params.packId;
  const navigate = useNavigate();
  const toast = useToast();

  const { data: pack, isLoading, error, refetch } = usePack(packId);
  const applyMut = useApplyPack(packId ?? "");

  // Selected template keys. Default-select everything once the pack loads, so
  // the common "apply the whole pack" path is one click; the admin can
  // deselect rules they don't want before materializing.
  const [selected, setSelected] = useState<Set<string> | null>(null);
  const [confirming, setConfirming] = useState(false);

  const keys = useMemo(
    () => new Set((pack?.templates ?? []).map((t) => t.key)),
    [pack],
  );
  const sel = selected ?? keys;

  const toggle = (key: string) => {
    const next = new Set(sel);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    setSelected(next);
  };

  const allSelected = pack ? sel.size === pack.templates.length : false;
  const toggleAll = () => {
    if (!pack) return;
    setSelected(allSelected ? new Set() : new Set(keys));
  };

  const apply = async () => {
    if (!pack || sel.size === 0) return;
    const chosen = pack.templates
      .map((t) => t.key)
      .filter((k) => sel.has(k));
    try {
      const res = await applyMut.mutateAsync(
        // Send undefined when the whole pack is selected so the API applies all.
        chosen.length === pack.templates.length ? undefined : chosen,
      );
      setConfirming(false);
      toast.success(
        `${res.count} draft ${res.count === 1 ? "policy" : "policies"} created`,
        "Simulate and promote each one before it can take effect.",
      );
      navigate({ to: "/policies" });
    } catch (e) {
      setConfirming(false);
      toast.error(
        "Could not apply pack",
        e instanceof Error ? e.message : "Please try again.",
      );
    }
  };

  return (
    <>
      <button
        className="btn btn--ghost btn--sm"
        onClick={() => navigate({ to: "/packs" })}
        style={{ marginBottom: 12 }}
      >
        ← All packs
      </button>

      <AsyncBoundary
        isLoading={isLoading}
        error={error}
        data={pack}
        onRetry={refetch}
      >
        {(p) => (
          <>
            <PageHeader title={p.name} subtitle={p.description} />

            <Card className="pack-meta">
              <dl className="pack-meta__grid">
                <Meta label="Authority" value={p.authority} />
                <Meta
                  label="Frameworks"
                  value={
                    <span className="pack-card__tags">
                      {p.frameworks.map((f) => (
                        <Badge key={f} tone="info">
                          {f}
                        </Badge>
                      ))}
                    </span>
                  }
                />
                <Meta label="Regions" value={p.regions.join(", ")} />
                <Meta
                  label="Industries"
                  value={p.industries.join(", ")}
                />
              </dl>
            </Card>

            <Card
              title="Access rules in this pack"
              subtitle="Each rule materializes as a draft policy with smart-default subjects and resources. Remap them to your real groups and systems, then simulate before promoting."
              actions={
                <label className="pack-select-all">
                  <input
                    type="checkbox"
                    checked={allSelected}
                    onChange={toggleAll}
                  />
                  Select all
                </label>
              }
            >
              <div className="template-list">
                {p.templates.map((t) => (
                  <TemplateRow
                    key={t.key}
                    template={t}
                    checked={sel.has(t.key)}
                    onToggle={() => toggle(t.key)}
                  />
                ))}
              </div>
            </Card>

            <div className="pack-apply-bar">
              <span className="muted">
                {sel.size} of {p.templates.length} rule
                {p.templates.length === 1 ? "" : "s"} selected
              </span>
              <button
                className="btn btn--primary"
                disabled={sel.size === 0 || applyMut.isPending}
                onClick={() => setConfirming(true)}
              >
                Apply as drafts
              </button>
            </div>

            {confirming && (
              <Modal
                title="Apply pack as draft policies?"
                onClose={() => setConfirming(false)}
                footer={
                  <>
                    <button
                      className="btn btn--ghost"
                      onClick={() => setConfirming(false)}
                    >
                      Cancel
                    </button>
                    <button
                      className="btn btn--primary"
                      onClick={apply}
                      disabled={applyMut.isPending}
                    >
                      {applyMut.isPending
                        ? "Applying…"
                        : `Create ${sel.size} draft${sel.size === 1 ? "" : "s"}`}
                    </button>
                  </>
                }
              >
                <p>
                  This creates <b>{sel.size}</b> draft{" "}
                  {sel.size === 1 ? "policy" : "policies"} in your workspace from{" "}
                  <b>{p.name}</b>. Drafts are inert — each must be{" "}
                  <b>simulated and promoted</b> before it changes who can reach
                  what. Nothing takes effect now.
                </p>
              </Modal>
            )}
          </>
        )}
      </AsyncBoundary>
    </>
  );
}

function Meta({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="pack-meta__item">
      <dt>{label}</dt>
      <dd>{value}</dd>
    </div>
  );
}

function TemplateRow({
  template,
  checked,
  onToggle,
}: {
  template: PackTemplate;
  checked: boolean;
  onToggle: () => void;
}) {
  return (
    <label className={`template-row${checked ? " is-selected" : ""}`}>
      <input type="checkbox" checked={checked} onChange={onToggle} />
      <div className="template-row__main">
        <div className="template-row__head">
          <b>{template.name}</b>
          <Badge tone={template.action === "deny" ? "danger" : "ok"}>
            {template.action === "deny" ? "Deny" : "Grant"}
          </Badge>
          {template.role && <Badge tone="neutral">role: {template.role}</Badge>}
        </div>
        <p className="template-row__summary">{template.summary}</p>
        <div className="template-row__rule">
          <span className="template-row__chips">
            {template.subjects.map((s) => (
              <code key={s} className="chip chip--subject">
                {s}
              </code>
            ))}
          </span>
          <span className="template-row__arrow" aria-hidden>
            →
          </span>
          <span className="template-row__chips">
            {template.resources.map((r) => (
              <code key={r} className="chip chip--resource">
                {r}
              </code>
            ))}
          </span>
        </div>
        <span className="template-row__control muted">{template.control}</span>
      </div>
    </label>
  );
}
