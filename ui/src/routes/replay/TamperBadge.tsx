import { FormattedMessage } from "react-intl";
import { Badge } from "@/components/ui";
import { HelpTooltip } from "@/components/HelpTooltip";

// TamperBadge renders the recording's integrity verdict. `verified` is the
// authoritative signal: the blob was re-hashed on read and matched the SHA-256
// the gateway anchored in the per-workspace audit hash chain at capture.
// `anchored` reports whether such a digest existed to compare against — an
// un-anchored recording can be displayed but not cryptographically attested.
export function TamperBadge({
  anchored,
  verified,
}: {
  anchored: boolean;
  verified: boolean;
}) {
  if (verified) {
    return (
      <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
        <Badge tone="ok" dot>
          <FormattedMessage defaultMessage="Integrity verified" />
        </Badge>
        <HelpTooltip title="Tamper-evidence">
          <FormattedMessage defaultMessage="The recording bytes were re-hashed on read and matched the SHA-256 digest anchored in this workspace's tamper-evident audit chain when the session was captured. The transcript has not been altered." />
        </HelpTooltip>
      </span>
    );
  }
  if (!anchored) {
    return (
      <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
        <Badge tone="neutral">
          <FormattedMessage defaultMessage="Not attested" />
        </Badge>
        <HelpTooltip title="Tamper-evidence">
          <FormattedMessage defaultMessage="No SHA-256 digest was anchored for this recording, so its integrity cannot be cryptographically verified. The transcript is shown for reference only." />
        </HelpTooltip>
      </span>
    );
  }
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
      <Badge tone="danger" dot>
        <FormattedMessage defaultMessage="Integrity FAILED" />
      </Badge>
      <HelpTooltip title="Tamper-evidence" align="right">
        <FormattedMessage defaultMessage="The recording's recomputed SHA-256 does not match the digest anchored in the audit chain at capture. The blob may be corrupted or tampered with — treat this transcript as untrustworthy and investigate." />
      </HelpTooltip>
    </span>
  );
}
