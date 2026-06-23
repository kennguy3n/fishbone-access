import { useIntl } from "react-intl";
import { Card } from "@/components/ui";
import { Icon } from "@/components/Icon";

interface Article {
  titleId: string;
  href: string;
}

const ARTICLES: Article[] = [
  {
    titleId: "whatsnew.blog.hardwareSoftwareCloudFirewalls",
    href: "https://shieldnet360.com/blog/hardware-software-cloud-firewalls-compared",
  },
  {
    titleId: "whatsnew.blog.managingSaaSAppAccess",
    href: "https://shieldnet360.com/blog/managing-saas-app-access-visibility",
  },
  {
    titleId: "whatsnew.blog.phishingLink",
    href: "https://shieldnet360.com/blog/i-clicked-a-phishing-link-what-to-do",
  },
];

export function WhatsNewCard() {
  const intl = useIntl();
  return (
    <Card
      title={intl.formatMessage({
        id: "whatsnew.title",
        defaultMessage: "What's new",
      })}
      subtitle={intl.formatMessage({
        id: "whatsnew.subtitle",
        defaultMessage: "Latest guidance and updates from ShieldNet 360.",
      })}
    >
      <ul className="whatsnew-list">
        {ARTICLES.map((article, idx) => (
          <li key={idx}>
            <a
              href={article.href}
              target="_blank"
              rel="noreferrer"
              className="whatsnew-item"
            >
              <Icon name="updates" size={16} />
              <span className="whatsnew-item__title">
                {intl.formatMessage({ id: article.titleId })}
              </span>
            </a>
          </li>
        ))}
      </ul>
      <a
        href="https://shieldnet360.com/blog"
        target="_blank"
        rel="noreferrer"
        className="whatsnew-footer"
      >
        <span>
          <b>{intl.formatMessage({ id: "whatsnew.updates.title" })}</b>
          <span className="muted">
            {intl.formatMessage({ id: "whatsnew.updates.desc" })}
          </span>
        </span>
        <span className="whatsnew-footer__cta">
          {intl.formatMessage({
            id: "whatsnew.readMore",
            defaultMessage: "Read more",
          })}
          <Icon name="chevron-down" size={14} />
        </span>
      </a>
    </Card>
  );
}
