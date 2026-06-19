// Lane-shared display labels for the wire-level enums the Connectors,
// Discovery and Web-access screens surface. Two concerns live here:
//
//  1. Acronym casing. Protocol tokens arrive lower-case ("ssh", "mysql") and
//     are rendered inside `.badge { text-transform: capitalize }`, which would
//     mangle acronyms into "Ssh"/"Mysql". `protocolLabel` returns the correct
//     brand casing ("SSH", "MySQL", "PostgreSQL") that survives `capitalize`.
//  2. Localization. Status / source / trigger enums were previously printed
//     raw (or via an English-only constant); these helpers route every
//     user-facing label through react-intl so no string is hard-coded.
//
// Pure label mapping only — no JSX — so any owned screen can consume it.

import type { IntlShape } from "react-intl";
import { titleCase } from "@/lib/format";

const PROTOCOL_LABELS: Record<string, string> = {
  ssh: "SSH",
  rdp: "RDP",
  vnc: "VNC",
  postgres: "PostgreSQL",
  mysql: "MySQL",
  mssql: "SQL Server",
  mongodb: "MongoDB",
  redis: "Redis",
};

/**
 * Correctly-cased, brand-accurate label for a wire protocol token. Acronyms
 * stay upper-case where `text-transform: capitalize` alone would mangle them;
 * unknown protocols fall back to title case so nothing renders as a raw slug.
 */
export function protocolLabel(raw: string | undefined | null): string {
  if (!raw) return "";
  const key = raw.trim().toLowerCase();
  return PROTOCOL_LABELS[key] ?? titleCase(raw);
}

// Brand acronyms that plain titleCase would flatten inside a category label
// ("saas_application" -> "Saas Application"). Categories are a controlled
// backend taxonomy, so a token-level casing pass is enough to keep them
// on-brand without translating the vocabulary itself.
const CATEGORY_ACRONYMS: Record<string, string> = {
  saas: "SaaS",
  hr: "HR",
  it: "IT",
  itsm: "ITSM",
  crm: "CRM",
  erp: "ERP",
  api: "API",
  mdm: "MDM",
  siem: "SIEM",
  pam: "PAM",
  iam: "IAM",
};

/**
 * Display label for a connector category slug, preserving brand acronym casing
 * that plain titleCase would mangle (e.g. "saas_application" -> "SaaS
 * Application"). Shared so the gallery, category filter and the setup-assistant
 * subtitle all render categories identically.
 */
export function categoryLabel(raw: string | undefined | null): string {
  if (!raw) return "";
  return raw
    .trim()
    .toLowerCase()
    .split(/[_\s]+/)
    .filter(Boolean)
    .map((w) => CATEGORY_ACRONYMS[w] ?? w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

/** Localized label for a discovered-asset lifecycle status. */
export function assetStatusLabel(intl: IntlShape, status: string): string {
  switch (status) {
    case "managed":
      return intl.formatMessage({
        id: "discovery.assetStatus.managed",
        defaultMessage: "Managed",
      });
    case "unmanaged":
      return intl.formatMessage({
        id: "discovery.assetStatus.unmanaged",
        defaultMessage: "Unmanaged",
      });
    case "orphan":
      return intl.formatMessage({
        id: "discovery.assetStatus.orphan",
        defaultMessage: "Orphaned",
      });
    case "ignored":
      return intl.formatMessage({
        id: "discovery.assetStatus.ignored",
        defaultMessage: "Ignored",
      });
    default:
      return titleCase(status);
  }
}

/** Localized label for a discovery scan run status. */
export function scanStatusLabel(intl: IntlShape, status: string): string {
  switch (status) {
    case "completed":
      return intl.formatMessage({
        id: "discovery.scanStatus.completed",
        defaultMessage: "Completed",
      });
    case "running":
      return intl.formatMessage({
        id: "discovery.scanStatus.running",
        defaultMessage: "Running",
      });
    case "failed":
      return intl.formatMessage({
        id: "discovery.scanStatus.failed",
        defaultMessage: "Failed",
      });
    default:
      return titleCase(status);
  }
}

/** Localized label for what kicked off a discovery scan. */
export function scanTriggerLabel(intl: IntlShape, trigger: string): string {
  switch (trigger) {
    case "manual":
      return intl.formatMessage({
        id: "discovery.scanTrigger.manual",
        defaultMessage: "Manual",
      });
    case "scheduled":
      return intl.formatMessage({
        id: "discovery.scanTrigger.scheduled",
        defaultMessage: "Scheduled",
      });
    case "api":
      return intl.formatMessage({
        id: "discovery.scanTrigger.api",
        defaultMessage: "API",
      });
    default:
      return titleCase(trigger);
  }
}

/** Localized label for the source a discovered asset / scan came from. */
export function sourceLabel(intl: IntlShape, source: string): string {
  switch (source) {
    case "agent_sweep":
    case "agent":
      return intl.formatMessage({
        id: "discovery.source.agent",
        defaultMessage: "Agent network",
      });
    case "connector_inventory":
    case "connector":
      return intl.formatMessage({
        id: "discovery.source.connector",
        defaultMessage: "Cloud connector",
      });
    case "db_accounts":
    case "db":
      return intl.formatMessage({
        id: "discovery.source.db",
        defaultMessage: "Database",
      });
    default:
      return titleCase(source);
  }
}
