package packs

// This file is the curated pack catalog. It is intentionally data-heavy and
// has no behaviour of its own — ListPacks/FindPack/Apply (packs.go) operate
// over whatever Catalog returns.
//
// Template subjects/resources follow the editor's reference conventions
// (SUBJECT_HINTS: user:/team:/contractor:/group:/role:, RESOURCE_HINTS:
// app:/host:/service:/db:/*). They are *smart defaults*: an SME admin remaps
// "team:finance" or "db:cardholder" to their real groups and systems before
// simulating. Nothing here is enforced until each materialized draft is
// simulated and promoted.
//
// Tiers:
//   1 — global compliance frameworks (PCI-DSS, HIPAA, GDPR, SOC 2, ISO 27001)
//   2 — South-East Asia data-protection regimes
//   3 — remaining target jurisdictions (GCC/UAE, AU, UK, US, CH, DE, FR, LATAM)

// catalog is built once at package init; the slice is treated as immutable.
var catalog = buildCatalog()

// Catalog returns the full pack catalog.
func Catalog() []Pack { return catalog }

func buildCatalog() []Pack {
	packs := make([]Pack, 0, 32)
	packs = append(packs, tier1Global()...)
	packs = append(packs, tier2SEA()...)
	packs = append(packs, tier3Rest()...)
	return packs
}

// ---------------------------------------------------------------------------
// Tier 1 — global compliance frameworks
// ---------------------------------------------------------------------------

func tier1Global() []Pack {
	return []Pack{
		{
			ID:          "pci-dss-v4",
			Name:        "PCI-DSS v4.0 — Cardholder Data Environment",
			Authority:   "PCI Security Standards Council",
			Description: "Least-privilege access to the cardholder data environment (CDE): restrict who can reach systems storing or processing cardholder data, and keep contractors and general staff out by default.",
			Tier:        1,
			Regions:     []string{"global"},
			Industries:  []string{"finance", "retail", "ecommerce", "saas"},
			Frameworks:  []string{"PCI-DSS"},
			Templates: []Template{
				{
					Key: "cde-admins-only", Name: "CDE administration — payments team only",
					Summary: "Grant the payments operations team admin access to the cardholder data environment.",
					Action:  "grant", Subjects: []string{"team:payments-ops"}, Resources: []string{"app:payment-gateway", "db:cardholder"}, Role: "admin",
					Control: "PCI-DSS 7.2 — Restrict access by business need-to-know",
				},
				{
					Key: "cde-deny-contractors", Name: "Block contractors from the CDE",
					Summary: "Deny all contractor identities access to cardholder systems.",
					Action:  "deny", Subjects: []string{"contractor:*"}, Resources: []string{"app:payment-gateway", "db:cardholder"},
					Control: "PCI-DSS 7.2.1 — Need-to-know for third parties",
				},
				{
					Key: "cde-deny-default", Name: "Deny-all to cardholder data by default",
					Summary: "Default-deny everyone to the cardholder database; grant back explicitly.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:cardholder"},
					Control: "PCI-DSS 7.3 — Default-deny access control system",
				},
			},
		},
		{
			ID:          "hipaa-security-rule",
			Name:        "HIPAA Security Rule — ePHI access",
			Authority:   "U.S. HHS Office for Civil Rights",
			Description: "Role-based access to electronic protected health information (ePHI): clinical staff get access to patient records, everyone else is denied, and break-glass is reserved for on-call responders.",
			Tier:        1,
			Regions:     []string{"global", "us"},
			Industries:  []string{"healthcare"},
			Frameworks:  []string{"HIPAA"},
			Templates: []Template{
				{
					Key: "ephi-clinical-access", Name: "Clinical staff → patient records",
					Summary: "Grant clinicians read/write access to the EHR system.",
					Action:  "grant", Subjects: []string{"team:clinical"}, Resources: []string{"app:ehr", "db:patient-records"}, Role: "clinician",
					Control: "HIPAA §164.312(a)(1) — Access control",
				},
				{
					Key: "ephi-deny-nonclinical", Name: "Deny non-clinical staff to ePHI",
					Summary: "Deny general/administrative staff direct access to patient records.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:patient-records"},
					Control: "HIPAA §164.308(a)(4) — Information access management",
				},
				{
					Key: "ephi-breakglass", Name: "Break-glass — on-call responders",
					Summary: "Grant the incident-response on-call group emergency access to ePHI (audited, simulate before promoting).",
					Action:  "grant", Subjects: []string{"role:incident-responder"}, Resources: []string{"app:ehr"}, Role: "break-glass",
					Control: "HIPAA §164.312(a)(2)(ii) — Emergency access procedure",
				},
			},
		},
		{
			ID:          "gdpr-personal-data",
			Name:        "GDPR — personal data least privilege",
			Authority:   "European Data Protection Board",
			Description: "Limit access to systems holding EU personal data to staff with a processing purpose, and deny broad/default access in line with data-minimisation and integrity & confidentiality.",
			Tier:        1,
			Regions:     []string{"global", "eu"},
			Industries:  []string{"any"},
			Frameworks:  []string{"GDPR"},
			Templates: []Template{
				{
					Key: "pii-purpose-access", Name: "Data team → customer PII store",
					Summary: "Grant the data team access to the customer PII database for defined processing.",
					Action:  "grant", Subjects: []string{"team:data"}, Resources: []string{"db:customer-pii"}, Role: "processor",
					Control: "GDPR Art. 5(1)(c) — Data minimisation",
				},
				{
					Key: "pii-deny-default", Name: "Deny-all to customer PII by default",
					Summary: "Default-deny the whole organisation to the PII store; grant back by purpose.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:customer-pii"},
					Control: "GDPR Art. 32 — Integrity and confidentiality",
				},
			},
		},
		{
			ID:          "soc2-logical-access",
			Name:        "SOC 2 — logical access controls",
			Authority:   "AICPA Trust Services Criteria",
			Description: "Common-Criteria logical access: production systems restricted to engineering/SRE, privileged access limited to admins, and default-deny for the rest.",
			Tier:        1,
			Regions:     []string{"global"},
			Industries:  []string{"saas", "any"},
			Frameworks:  []string{"SOC 2"},
			Templates: []Template{
				{
					Key: "prod-engineering", Name: "Engineering → production apps",
					Summary: "Grant engineering access to production application systems.",
					Action:  "grant", Subjects: []string{"team:engineering"}, Resources: []string{"app:production"}, Role: "operator",
					Control: "SOC 2 CC6.1 — Logical access security",
				},
				{
					Key: "prod-admin-restrict", Name: "Privileged prod access — admins only",
					Summary: "Grant the platform-admin group admin access to production infrastructure.",
					Action:  "grant", Subjects: []string{"role:platform-admin"}, Resources: []string{"host:prod"}, Role: "admin",
					Control: "SOC 2 CC6.3 — Least privilege & segregation",
				},
				{
					Key: "prod-deny-default", Name: "Deny-all to production by default",
					Summary: "Default-deny the organisation to production hosts; grant back per role.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"host:prod"},
					Control: "SOC 2 CC6.1 — Default-deny",
				},
			},
		},
		{
			ID:          "iso27001-annexa",
			Name:        "ISO/IEC 27001 Annex A — access control",
			Authority:   "ISO/IEC",
			Description: "Annex A.5 access-control baseline: business-need-driven access to information systems, restricted privileged utilities, and a default-deny posture.",
			Tier:        1,
			Regions:     []string{"global"},
			Industries:  []string{"any"},
			Frameworks:  []string{"ISO 27001"},
			Templates: []Template{
				{
					Key: "info-need-to-know", Name: "Business need-to-know access",
					Summary: "Grant a department access to its own line-of-business application.",
					Action:  "grant", Subjects: []string{"team:operations"}, Resources: []string{"app:erp"}, Role: "user",
					Control: "ISO 27001 A.5.15 — Access control",
				},
				{
					Key: "privileged-utilities", Name: "Restrict privileged utility access",
					Summary: "Grant only the sysadmin role access to privileged admin tooling.",
					Action:  "grant", Subjects: []string{"role:sysadmin"}, Resources: []string{"service:admin-console"}, Role: "admin",
					Control: "ISO 27001 A.8.18 — Use of privileged utility programs",
				},
				{
					Key: "iso-deny-default", Name: "Default-deny information systems",
					Summary: "Deny everyone by default; grant access by business need.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"service:admin-console"},
					Control: "ISO 27001 A.5.15 — Default-deny",
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Tier 2 — South-East Asia
// ---------------------------------------------------------------------------

func tier2SEA() []Pack {
	return []Pack{
		{
			ID:          "vn-pdpd-decree13",
			Name:        "Vietnam — PDPD (Decree 13/2023)",
			Authority:   "Ministry of Public Security (A05)",
			Description: "Personal Data Protection Decree baseline: restrict access to personal data, separate sensitive-data handling, and deny default access to comply with Decree 13's processing-purpose rules.",
			Tier:        2,
			Regions:     []string{"vn"},
			Industries:  []string{"any"},
			Frameworks:  []string{"PDPD", "Decree 13"},
			Templates: []Template{
				{
					Key: "vn-pii-access", Name: "Authorised processors → personal data",
					Summary: "Grant the data-processing team access to the personal-data store.",
					Action:  "grant", Subjects: []string{"team:data"}, Resources: []string{"db:personal-data"}, Role: "processor",
					Control: "Decree 13 Art. 3 — Processing principles",
				},
				{
					Key: "vn-sensitive-deny", Name: "Restrict sensitive personal data",
					Summary: "Deny general staff access to sensitive personal data categories.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:sensitive-data"},
					Control: "Decree 13 Art. 2(4) — Sensitive personal data",
				},
			},
		},
		{
			ID:          "sg-pdpa-mas-trm",
			Name:        "Singapore — PDPA + MAS TRM",
			Authority:   "PDPC / Monetary Authority of Singapore",
			Description: "PDPA protection obligation plus MAS Technology Risk Management access guidance: least-privilege to customer data and strict control of privileged access in financial systems.",
			Tier:        2,
			Regions:     []string{"sg"},
			Industries:  []string{"finance", "saas", "any"},
			Frameworks:  []string{"PDPA", "MAS TRM"},
			Templates: []Template{
				{
					Key: "sg-customer-data", Name: "Service team → customer data",
					Summary: "Grant the customer-service team access to the customer database.",
					Action:  "grant", Subjects: []string{"team:customer-service"}, Resources: []string{"db:customer"}, Role: "agent",
					Control: "PDPA — Protection Obligation (s24)",
				},
				{
					Key: "sg-privileged-control", Name: "Privileged access — admins only",
					Summary: "Restrict privileged access to core banking systems to the admin role.",
					Action:  "grant", Subjects: []string{"role:platform-admin"}, Resources: []string{"app:core-banking"}, Role: "admin",
					Control: "MAS TRM §11 — Access control",
				},
				{
					Key: "sg-deny-default", Name: "Default-deny customer data",
					Summary: "Deny the organisation to the customer database by default.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:customer"},
					Control: "PDPA — Reasonable security arrangements",
				},
			},
		},
		{
			ID:          "th-pdpa",
			Name:        "Thailand — PDPA",
			Authority:   "PDPC Thailand",
			Description: "Thai Personal Data Protection Act baseline: limit access to personal data to staff with a lawful basis and deny default access.",
			Tier:        2,
			Regions:     []string{"th"},
			Industries:  []string{"any"},
			Frameworks:  []string{"PDPA"},
			Templates: []Template{
				{
					Key: "th-pii-access", Name: "Authorised staff → personal data",
					Summary: "Grant the data team access to the personal-data store.",
					Action:  "grant", Subjects: []string{"team:data"}, Resources: []string{"db:personal-data"}, Role: "processor",
					Control: "PDPA Thailand s37 — Security measures",
				},
				{
					Key: "th-deny-default", Name: "Default-deny personal data",
					Summary: "Deny general staff access to personal data by default.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:personal-data"},
					Control: "PDPA Thailand s37 — Access restriction",
				},
			},
		},
		{
			ID:          "id-pdp-law",
			Name:        "Indonesia — PDP Law (UU PDP)",
			Authority:   "Kementerian Kominfo",
			Description: "Indonesia Personal Data Protection Law baseline: purpose-bound access to personal data with default-deny for the wider organisation.",
			Tier:        2,
			Regions:     []string{"id"},
			Industries:  []string{"any"},
			Frameworks:  []string{"PDP Law"},
			Templates: []Template{
				{
					Key: "id-pii-access", Name: "Authorised processors → personal data",
					Summary: "Grant the data-processing team access to personal data.",
					Action:  "grant", Subjects: []string{"team:data"}, Resources: []string{"db:personal-data"}, Role: "processor",
					Control: "UU PDP Art. 35 — Data protection",
				},
				{
					Key: "id-deny-default", Name: "Default-deny personal data",
					Summary: "Deny general staff access to personal data by default.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:personal-data"},
					Control: "UU PDP Art. 35 — Security obligation",
				},
			},
		},
		{
			ID:          "my-pdpa",
			Name:        "Malaysia — PDPA 2010",
			Authority:   "Jabatan Perlindungan Data Peribadi (JPDP)",
			Description: "Malaysia Personal Data Protection Act security-principle baseline: restrict personal-data access to authorised staff and default-deny the rest.",
			Tier:        2,
			Regions:     []string{"my"},
			Industries:  []string{"any"},
			Frameworks:  []string{"PDPA"},
			Templates: []Template{
				{
					Key: "my-pii-access", Name: "Authorised staff → personal data",
					Summary: "Grant the data team access to the personal-data store.",
					Action:  "grant", Subjects: []string{"team:data"}, Resources: []string{"db:personal-data"}, Role: "processor",
					Control: "PDPA Malaysia — Security Principle",
				},
				{
					Key: "my-deny-default", Name: "Default-deny personal data",
					Summary: "Deny general staff access to personal data by default.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:personal-data"},
					Control: "PDPA Malaysia — Security Principle",
				},
			},
		},
		{
			ID:          "ph-dpa",
			Name:        "Philippines — Data Privacy Act",
			Authority:   "National Privacy Commission",
			Description: "Philippines Data Privacy Act baseline: access to personal data limited to authorised personnel with default-deny.",
			Tier:        2,
			Regions:     []string{"ph"},
			Industries:  []string{"any"},
			Frameworks:  []string{"DPA"},
			Templates: []Template{
				{
					Key: "ph-pii-access", Name: "Authorised personnel → personal data",
					Summary: "Grant the data team access to personal data.",
					Action:  "grant", Subjects: []string{"team:data"}, Resources: []string{"db:personal-data"}, Role: "processor",
					Control: "DPA 2012 §20 — Security of personal information",
				},
				{
					Key: "ph-deny-default", Name: "Default-deny personal data",
					Summary: "Deny general staff access to personal data by default.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:personal-data"},
					Control: "DPA 2012 §20 — Access control",
				},
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Tier 3 — remaining target jurisdictions
// ---------------------------------------------------------------------------

func tier3Rest() []Pack {
	return []Pack{
		{
			ID:          "ae-pdpl-desc",
			Name:        "UAE — PDPL + DESC",
			Authority:   "UAE Data Office / Dubai Electronic Security Center",
			Description: "UAE Personal Data Protection Law and DESC information-security baseline: least-privilege access to personal data and tightly controlled privileged access.",
			Tier:        3,
			Regions:     []string{"ae"},
			Industries:  []string{"finance", "government", "any"},
			Frameworks:  []string{"PDPL", "DESC"},
			Templates: []Template{
				{
					Key: "ae-pii-access", Name: "Authorised staff → personal data",
					Summary: "Grant the data team access to the personal-data store.",
					Action:  "grant", Subjects: []string{"team:data"}, Resources: []string{"db:personal-data"}, Role: "processor",
					Control: "UAE PDPL Art. 9 — Security of processing",
				},
				{
					Key: "ae-privileged", Name: "Privileged access — admins only",
					Summary: "Restrict privileged access to the admin role.",
					Action:  "grant", Subjects: []string{"role:platform-admin"}, Resources: []string{"service:admin-console"}, Role: "admin",
					Control: "DESC ISR — Access control",
				},
				{
					Key: "ae-deny-default", Name: "Default-deny personal data",
					Summary: "Deny general staff access to personal data by default.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:personal-data"},
					Control: "UAE PDPL Art. 9 — Access restriction",
				},
			},
		},
		{
			ID:          "au-privacy-e8",
			Name:        "Australia — Privacy Act + Essential Eight",
			Authority:   "OAIC / Australian Cyber Security Centre",
			Description: "Australian Privacy Principles plus ACSC Essential Eight 'restrict administrative privileges': purpose-bound access to personal information and admin-only privileged access.",
			Tier:        3,
			Regions:     []string{"au"},
			Industries:  []string{"any"},
			Frameworks:  []string{"Privacy Act", "Essential Eight"},
			Templates: []Template{
				{
					Key: "au-pii-access", Name: "Authorised staff → personal information",
					Summary: "Grant the data team access to the personal-information store.",
					Action:  "grant", Subjects: []string{"team:data"}, Resources: []string{"db:personal-data"}, Role: "processor",
					Control: "APP 11 — Security of personal information",
				},
				{
					Key: "au-restrict-admin", Name: "Restrict administrative privileges",
					Summary: "Grant privileged infrastructure access to admins only.",
					Action:  "grant", Subjects: []string{"role:platform-admin"}, Resources: []string{"host:prod"}, Role: "admin",
					Control: "Essential Eight — Restrict administrative privileges",
				},
				{
					Key: "au-deny-default", Name: "Default-deny personal information",
					Summary: "Deny general staff access to personal information by default.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:personal-data"},
					Control: "APP 11 — Access restriction",
				},
			},
		},
		{
			ID:          "uk-gdpr-dpa2018",
			Name:        "United Kingdom — UK GDPR / DPA 2018",
			Authority:   "Information Commissioner's Office (ICO)",
			Description: "UK GDPR and Data Protection Act 2018 baseline: limit access to personal data to staff with a processing purpose and default-deny the wider organisation.",
			Tier:        3,
			Regions:     []string{"uk"},
			Industries:  []string{"any"},
			Frameworks:  []string{"UK GDPR", "DPA 2018"},
			Templates: []Template{
				{
					Key: "uk-pii-access", Name: "Data team → personal data",
					Summary: "Grant the data team access to the personal-data store for defined processing.",
					Action:  "grant", Subjects: []string{"team:data"}, Resources: []string{"db:personal-data"}, Role: "processor",
					Control: "UK GDPR Art. 5(1)(f) — Integrity and confidentiality",
				},
				{
					Key: "uk-deny-default", Name: "Default-deny personal data",
					Summary: "Deny the organisation to personal data by default.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:personal-data"},
					Control: "UK GDPR Art. 32 — Security of processing",
				},
			},
		},
		{
			ID:          "us-ccpa-cpra",
			Name:        "United States — CCPA / CPRA (California)",
			Authority:   "California Privacy Protection Agency",
			Description: "California Consumer Privacy Act / CPRA baseline: restrict access to consumer personal information and apply reasonable security with default-deny.",
			Tier:        3,
			Regions:     []string{"us"},
			Industries:  []string{"retail", "ecommerce", "saas", "any"},
			Frameworks:  []string{"CCPA", "CPRA"},
			Templates: []Template{
				{
					Key: "us-consumer-data", Name: "Authorised staff → consumer data",
					Summary: "Grant the data team access to the consumer personal-information store.",
					Action:  "grant", Subjects: []string{"team:data"}, Resources: []string{"db:consumer-pii"}, Role: "processor",
					Control: "CPRA §1798.100(e) — Reasonable security",
				},
				{
					Key: "us-deny-default", Name: "Default-deny consumer data",
					Summary: "Deny general staff access to consumer data by default.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:consumer-pii"},
					Control: "CPRA §1798.100(e) — Access restriction",
				},
			},
		},
		{
			ID:          "ch-nfadp",
			Name:        "Switzerland — nFADP",
			Authority:   "Federal Data Protection and Information Commissioner",
			Description: "Revised Swiss Federal Act on Data Protection baseline: purpose-bound access to personal data with default-deny.",
			Tier:        3,
			Regions:     []string{"ch"},
			Industries:  []string{"finance", "any"},
			Frameworks:  []string{"nFADP"},
			Templates: []Template{
				{
					Key: "ch-pii-access", Name: "Data team → personal data",
					Summary: "Grant the data team access to the personal-data store.",
					Action:  "grant", Subjects: []string{"team:data"}, Resources: []string{"db:personal-data"}, Role: "processor",
					Control: "nFADP Art. 8 — Data security",
				},
				{
					Key: "ch-deny-default", Name: "Default-deny personal data",
					Summary: "Deny general staff access to personal data by default.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:personal-data"},
					Control: "nFADP Art. 8 — Access restriction",
				},
			},
		},
		{
			ID:          "de-bdsg-c5",
			Name:        "Germany — BDSG + BSI C5",
			Authority:   "BfDI / Bundesamt für Sicherheit in der Informationstechnik",
			Description: "German Federal Data Protection Act plus BSI Cloud Computing Compliance Criteria (C5) access controls: least-privilege to personal data and admin-controlled privileged access.",
			Tier:        3,
			Regions:     []string{"de"},
			Industries:  []string{"any"},
			Frameworks:  []string{"BDSG", "BSI C5"},
			Templates: []Template{
				{
					Key: "de-pii-access", Name: "Data team → personal data",
					Summary: "Grant the data team access to the personal-data store.",
					Action:  "grant", Subjects: []string{"team:data"}, Resources: []string{"db:personal-data"}, Role: "processor",
					Control: "BDSG §64 — Requirements for security of processing",
				},
				{
					Key: "de-privileged", Name: "Privileged access — admins only",
					Summary: "Restrict privileged infrastructure access to the admin role.",
					Action:  "grant", Subjects: []string{"role:platform-admin"}, Resources: []string{"host:prod"}, Role: "admin",
					Control: "BSI C5 — IDM (identity & access management)",
				},
				{
					Key: "de-deny-default", Name: "Default-deny personal data",
					Summary: "Deny general staff access to personal data by default.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:personal-data"},
					Control: "BDSG §64 — Access restriction",
				},
			},
		},
		{
			ID:          "fr-cnil",
			Name:        "France — CNIL (GDPR)",
			Authority:   "Commission Nationale de l'Informatique et des Libertés",
			Description: "CNIL security guidance under GDPR: authenticate and authorise access to personal data on a need-to-know basis with default-deny.",
			Tier:        3,
			Regions:     []string{"fr"},
			Industries:  []string{"any"},
			Frameworks:  []string{"CNIL", "GDPR"},
			Templates: []Template{
				{
					Key: "fr-pii-access", Name: "Data team → personal data",
					Summary: "Grant the data team access to the personal-data store.",
					Action:  "grant", Subjects: []string{"team:data"}, Resources: []string{"db:personal-data"}, Role: "processor",
					Control: "CNIL — Manage user authorisations",
				},
				{
					Key: "fr-deny-default", Name: "Default-deny personal data",
					Summary: "Deny general staff access to personal data by default.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:personal-data"},
					Control: "CNIL — Least privilege",
				},
			},
		},
		{
			ID:          "br-lgpd",
			Name:        "Brazil — LGPD",
			Authority:   "Autoridade Nacional de Proteção de Dados (ANPD)",
			Description: "Brazilian General Data Protection Law baseline: restrict access to personal data to authorised agents with default-deny.",
			Tier:        3,
			Regions:     []string{"br"},
			Industries:  []string{"any"},
			Frameworks:  []string{"LGPD"},
			Templates: []Template{
				{
					Key: "br-pii-access", Name: "Authorised agents → personal data",
					Summary: "Grant the data team access to the personal-data store.",
					Action:  "grant", Subjects: []string{"team:data"}, Resources: []string{"db:personal-data"}, Role: "processor",
					Control: "LGPD Art. 46 — Security measures",
				},
				{
					Key: "br-deny-default", Name: "Default-deny personal data",
					Summary: "Deny general staff access to personal data by default.",
					Action:  "deny", Subjects: []string{"group:all-staff"}, Resources: []string{"db:personal-data"},
					Control: "LGPD Art. 46 — Access restriction",
				},
			},
		},
	}
}
