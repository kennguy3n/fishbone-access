import { useMemo, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useIntl } from "react-intl";
import { useLaneA5Scope } from "./lane-a5";
import { PageHeader, Card, Badge, AsyncBoundary } from "@/components/ui";
import { EmptyState } from "@/components/EmptyState";
import { usePacks, type Pack } from "@/api/access";

// Tier groupings mirror the backend catalog (internal/services/packs):
//   1 — global compliance frameworks (PCI-DSS, HIPAA, GDPR, SOC 2, ISO 27001)
//   2 — South-East Asia data-protection regimes
//   3 — remaining jurisdictions (GCC/UAE, AU, UK, US, CH, DE, FR, LATAM)
const TIERS: { value: number | undefined; id: string; label: string }[] = [
  { value: undefined, id: "packs.tier.all", label: "All packs" },
  { value: 1, id: "packs.tier.global", label: "Global compliance" },
  { value: 2, id: "packs.tier.sea", label: "South-East Asia" },
  { value: 3, id: "packs.tier.row", label: "Rest of world" },
];

export function Packs() {
  useLaneA5Scope();
  const intl = useIntl();
  const navigate = useNavigate();
  const [tier, setTier] = useState<number | undefined>(undefined);
  const [framework, setFramework] = useState<string>("");
  const { data, isLoading, error, refetch } = usePacks();

  // Filter client-side so changing a chip is instant and never re-fetches —
  // the whole curated catalog is small and already in memory.
  const frameworks = useMemo(() => {
    const set = new Set<string>();
    (data ?? []).forEach((p) => p.frameworks.forEach((f) => set.add(f)));
    return Array.from(set).sort();
  }, [data]);

  const visible = useMemo(() => {
    return (data ?? []).filter(
      (p) =>
        (tier === undefined || p.tier === tier) &&
        (framework === "" || p.frameworks.includes(framework)),
    );
  }, [data, tier, framework]);

  return (
    <>
      <PageHeader
        title={intl.formatMessage({
          id: "packs.title",
          defaultMessage: "Policy packs",
        })}
        subtitle={intl.formatMessage({
          id: "packs.subtitle",
          defaultMessage:
            "Curated, expert-built access rules for common compliance frameworks and regional data-protection laws. Applying a pack creates draft policies — nothing is enforced until you simulate and promote each one.",
        })}
      />

      <div
        className="pill-tabs"
        role="tablist"
        aria-label={intl.formatMessage({
          id: "packs.tier.aria",
          defaultMessage: "Pack tier",
        })}
      >
        {TIERS.map((t) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={tier === t.value}
            className={tier === t.value ? "active" : ""}
            onClick={() => setTier(t.value)}
          >
            {intl.formatMessage({ id: t.id, defaultMessage: t.label })}
          </button>
        ))}
      </div>

      <div className="filter-bar">
        <label className="muted" style={{ fontSize: 13 }} htmlFor="pack-framework">
          {intl.formatMessage({
            id: "packs.filter.framework",
            defaultMessage: "Framework",
          })}
        </label>
        <select
          id="pack-framework"
          value={framework}
          onChange={(e) => setFramework(e.target.value)}
          style={{ width: "auto", minWidth: 160 }}
        >
          <option value="">
            {intl.formatMessage({
              id: "packs.filter.allFrameworks",
              defaultMessage: "All frameworks",
            })}
          </option>
          {frameworks.map((f) => (
            <option key={f} value={f}>
              {f}
            </option>
          ))}
        </select>
        {(tier !== undefined || framework !== "") && (
          <button
            className="btn btn--ghost btn--sm"
            onClick={() => {
              setTier(undefined);
              setFramework("");
            }}
          >
            {intl.formatMessage({
              id: "packs.filter.clear",
              defaultMessage: "Clear filters",
            })}
          </button>
        )}
      </div>

      <AsyncBoundary
        isLoading={isLoading}
        error={error}
        data={visible}
        onRetry={refetch}
        isEmpty={(rows) => rows.length === 0}
        empty={
          <EmptyState
            title={intl.formatMessage({
              id: "packs.empty.title",
              defaultMessage: "No packs match these filters",
            })}
            description={intl.formatMessage({
              id: "packs.empty.body",
              defaultMessage:
                "Try a different tier or framework, or clear the filters to see the full catalog.",
            })}
          />
        }
      >
        {(rows) => (
          <div className="grid grid--2">
            {rows.map((p) => (
              <PackCard
                key={p.id}
                pack={p}
                onOpen={() =>
                  navigate({ to: "/packs/$packId", params: { packId: p.id } })
                }
              />
            ))}
          </div>
        )}
      </AsyncBoundary>
    </>
  );
}

function PackCard({ pack, onOpen }: { pack: Pack; onOpen: () => void }) {
  const intl = useIntl();
  return (
    <Card className="pack-card">
      <div className="pack-card__body">
        <div className="pack-card__head">
          <h3 className="pack-card__title">{pack.name}</h3>
          <span className="muted" style={{ fontSize: 12 }}>
            {pack.authority}
          </span>
        </div>
        <p className="pack-card__desc">{pack.description}</p>
        <div className="pack-card__tags">
          {pack.frameworks.map((f) => (
            <Badge key={f} tone="info">
              {f}
            </Badge>
          ))}
          {pack.regions.map((r) => (
            <Badge key={r} tone="neutral">
              {r}
            </Badge>
          ))}
        </div>
      </div>
      <div className="pack-card__foot">
        <span className="muted" style={{ fontSize: 12.5 }}>
          {intl.formatMessage(
            {
              id: "packs.card.ruleCount",
              defaultMessage: "{n, plural, one {# rule} other {# rules}}",
            },
            { n: pack.templates.length },
          )}
        </span>
        <button className="btn btn--primary btn--sm" onClick={onOpen}>
          {intl.formatMessage({
            id: "packs.card.review",
            defaultMessage: "Review & apply",
          })}
        </button>
      </div>
    </Card>
  );
}
