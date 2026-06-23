import { Link } from "@tanstack/react-router";
import { FormattedMessage, useIntl } from "react-intl";
import { Card } from "@/components/ui";
import { Icon, type IconName } from "@/components/Icon";

interface PamCard {
  icon: IconName;
  titleId: string;
  descId: string;
  to: string;
}

const PAM_CARDS: PamCard[] = [
  {
    icon: "key",
    titleId: "nav.pam.targets",
    descId: "pam.overview.targets.desc",
    to: "/pam/targets",
  },
  {
    icon: "integrations",
    titleId: "nav.pam.agents",
    descId: "pam.overview.agents.desc",
    to: "/pam/agents",
  },
  {
    icon: "playbooks",
    titleId: "nav.pam.leases",
    descId: "pam.overview.leases.desc",
    to: "/pam/leases",
  },
  {
    icon: "browser",
    titleId: "nav.pam.webAccess",
    descId: "pam.overview.webAccess.desc",
    to: "/pam/web-access",
  },
  {
    icon: "troubleshoot",
    titleId: "nav.pam.sessions",
    descId: "pam.overview.sessions.desc",
    to: "/pam/sessions",
  },
  {
    icon: "audit",
    titleId: "nav.pam.recordings",
    descId: "pam.overview.recordings.desc",
    to: "/pam/recordings",
  },
  {
    icon: "audit",
    titleId: "nav.pam.rotation",
    descId: "pam.overview.rotation.desc",
    to: "/pam/rotation",
  },
];

export function PamOverview() {
  const intl = useIntl();
  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1 className="page-title">
            <FormattedMessage id="pam.overview.title" />
          </h1>
          <p className="muted">
            <FormattedMessage id="pam.overview.subtitle" />
          </p>
        </div>
      </div>

      <div className="grid grid--3" style={{ marginTop: 12 }}>
        {PAM_CARDS.map((card) => (
          <Link key={card.to} to={card.to} className="pam-card">
            <div className="pam-card__icon">
              <Icon name={card.icon} size={22} />
            </div>
            <div className="pam-card__main">
              <b>{intl.formatMessage({ id: card.titleId })}</b>
              <span className="muted">
                {intl.formatMessage({ id: card.descId })}
              </span>
            </div>
            <span className="pam-card__arrow" aria-hidden>
              &rarr;
            </span>
          </Link>
        ))}
      </div>

      <Card
        title={intl.formatMessage({
          id: "help.faq.policy.q",
          defaultMessage: "What is an access policy?",
        })}
        subtitle={intl.formatMessage({
          id: "help.faq.policy.a",
          defaultMessage:
            "A policy is a rule that decides who can access what. You write it in plain terms, test it safely as a draft, then promote it to start enforcing access.",
        })}
        className="pam-policy-card"
      >
        <Link className="btn btn--primary btn--sm" to="/policies">
          {intl.formatMessage({
            id: "pam.overview.policyCta",
            defaultMessage: "Go to policies",
          })}
        </Link>
      </Card>
    </div>
  );
}
