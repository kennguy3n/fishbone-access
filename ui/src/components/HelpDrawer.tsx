import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { useIntl, type IntlShape } from "react-intl";
import { Icon, type IconName } from "@/components/Icon";
import { useHelpDrawer } from "./HelpDrawerContext";


export function HelpButton() {
  const { setOpen } = useHelpDrawer();
  const intl = useIntl();
  return (
    <button
      type="button"
      className="topbar__icon-btn"
      onClick={() => setOpen(true)}
      aria-label={intl.formatMessage({
        id: "help.drawer.title",
        defaultMessage: "Help & support",
      })}
      title={intl.formatMessage({
        id: "help.drawer.title",
        defaultMessage: "Help & support",
      })}
    >
      <Icon name="help" size={20} />
    </button>
  );
}

interface FAQItem {
  q: string;
  a: string;
}

function useFAQ(): FAQItem[] {
  const intl = useIntl();
  return useMemo(
    () => [
      {
        q: intl.formatMessage({
          id: "selfservice.help.jit.q",
          defaultMessage: "What is \u201Cjust-in-time\u201D access?",
        }),
        a: intl.formatMessage({
          id: "selfservice.help.jit.a",
          defaultMessage:
            "Instead of having access to everything all the time, you ask for it only when you need it. It's granted for a limited window and then removed automatically — which keeps everyone safer.",
        }),
      },
      {
        q: intl.formatMessage({
          id: "selfservice.help.time.q",
          defaultMessage: "How long does approval take?",
        }),
        a: intl.formatMessage({
          id: "selfservice.help.time.a",
          defaultMessage:
            "Low-risk requests can be approved automatically and are ready in moments. Others go to a reviewer; you'll see the status change here as soon as they decide.",
        }),
      },
      {
        q: intl.formatMessage({
          id: "selfservice.help.name.q",
          defaultMessage: "I don't know the exact name of what I need.",
        }),
        a: intl.formatMessage({
          id: "selfservice.help.name.a",
          defaultMessage:
            "Enter the closest name you know (like the app's name) and add a clear reason. If it's not quite right, an approver can help — or ask the colleague who pointed you here.",
        }),
      },
      {
        q: intl.formatMessage({
          id: "selfservice.help.expired.q",
          defaultMessage: "My access expired — what do I do?",
        }),
        a: intl.formatMessage({
          id: "selfservice.help.expired.a",
          defaultMessage:
            "That's normal for time-limited access. Just request it again using the form above; if you use it often, mention that in your reason.",
        }),
      },
      {
        q: intl.formatMessage({
          id: "help.faq.policy.q",
          defaultMessage: "What is an access policy?",
        }),
        a: intl.formatMessage({
          id: "help.faq.policy.a",
          defaultMessage:
            "A policy is a rule that decides who can access what. You write it in plain terms, test it safely as a draft, then promote it to start enforcing access.",
        }),
      },
      {
        q: intl.formatMessage({
          id: "help.faq.connector.q",
          defaultMessage: "What is a connector?",
        }),
        a: intl.formatMessage({
          id: "help.faq.connector.a",
          defaultMessage:
            "A connector links ShieldNet Access to where your people and apps live — like Google Workspace, Microsoft Entra, or AWS. Without a connector, policies can't target real users.",
        }),
      },
      {
        q: intl.formatMessage({
          id: "help.faq.score.q",
          defaultMessage: "How is the health score calculated?",
        }),
        a: intl.formatMessage({
          id: "help.faq.score.a",
          defaultMessage:
            "Your score starts at 100 and drops for untested drafts, open requests, accounts to clean up, and missing connectors. Fixing any of those items raises the score again.",
        }),
      },
      {
        q: intl.formatMessage({
          id: "help.faq.support.q",
          defaultMessage: "How do I contact support?",
        }),
        a: intl.formatMessage({
          id: "help.faq.support.a",
          defaultMessage:
            "Email us at support@shieldnet360.com or visit the website. We reply during business hours.",
        }),
      },
    ],
    [intl],
  );
}

export function HelpDrawer() {
  const { open, setOpen } = useHelpDrawer();
  const intl = useIntl();
  const [search, setSearch] = useState("");
  const [activeTab, setActiveTab] = useState<"help" | "chat">("help");
  const drawerRef = useRef<HTMLDivElement>(null);
  const faq = useFAQ();

  const filteredFAQ = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return faq;
    return faq.filter(
      (item) => item.q.toLowerCase().includes(q) || item.a.toLowerCase().includes(q),
    );
  }, [faq, search]);

  useEffect(() => {
    if (!open) return;
    const root = document.documentElement;
    const originalOverflow = root.style.overflow;
    root.style.overflow = "hidden";
    return () => {
      root.style.overflow = originalOverflow;
    };
  }, [open]);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && open) setOpen(false);
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, setOpen]);

  return (
    <div
      className={`help-drawer ${open ? "help-drawer--open" : ""}`}
      aria-hidden={!open}
      ref={drawerRef}
    >
      <div
        className="help-drawer__scrim"
        onClick={() => setOpen(false)}
        role="presentation"
      />
      <div
        className="help-drawer__panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="help-drawer-title"
      >
        <div className="help-drawer__header">
          <div>
            <h2 id="help-drawer-title" className="help-drawer__title">
              {intl.formatMessage({
                id: "help.drawer.title",
                defaultMessage: "Help & support",
              })}
            </h2>
            <p className="help-drawer__subtitle">
              {intl.formatMessage({
                id: "help.drawer.subtitle",
                defaultMessage: "Quick answers and ways to get unstuck.",
              })}
            </p>
          </div>
          <button
            type="button"
            className="btn btn--ghost btn--sm"
            onClick={() => setOpen(false)}
            aria-label={intl.formatMessage({
              id: "help.drawer.close",
              defaultMessage: "Close help",
            })}
          >
            <Icon name="close" size={18} />
          </button>
        </div>

        <div className="help-drawer__tabs">
          <button
            type="button"
            className={`help-drawer__tab ${activeTab === "help" ? "help-drawer__tab--active" : ""}`}
            onClick={() => setActiveTab("help")}
          >
            <Icon name="help" size={16} />
            {intl.formatMessage({
              id: "help.section.faq",
              defaultMessage: "Common questions",
            })}
          </button>
          <button
            type="button"
            className={`help-drawer__tab ${activeTab === "chat" ? "help-drawer__tab--active" : ""}`}
            onClick={() => setActiveTab("chat")}
          >
            <Icon name="chat" size={16} />
            {intl.formatMessage({
              id: "help.chat.title",
              defaultMessage: "Ask the assistant",
            })}
          </button>
        </div>

        {activeTab === "help" ? (
          <div className="help-drawer__body">
            <div className="help-drawer__search">
              <Icon name="search" size={16} />
              <input
                type="search"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={intl.formatMessage({
                  id: "help.search.placeholder",
                  defaultMessage: "Search help…",
                })}
              />
            </div>

            <div className="help-drawer__section">
              <h3 className="help-drawer__section-title">
                {intl.formatMessage({
                  id: "help.section.quickActions",
                  defaultMessage: "Quick actions",
                })}
              </h3>
              <div className="help-drawer__actions">
                <QuickAction
                  icon="rocket"
                  title={intl.formatMessage({
                    id: "help.quick.onboarding",
                    defaultMessage: "Get started",
                  })}
                  desc={intl.formatMessage({
                    id: "help.quick.onboarding.desc",
                    defaultMessage: "Walk through connecting your first source and writing your first rule.",
                  })}
                  to="/onboarding"
                />
                <QuickAction
                  icon="idp"
                  title={intl.formatMessage({
                    id: "help.quick.selfService",
                    defaultMessage: "Your access",
                  })}
                  desc={intl.formatMessage({
                    id: "help.quick.selfService.desc",
                    defaultMessage: "Request access, check what's approved, and read the FAQ.",
                  })}
                  to="/self-service"
                />
                <QuickAction
                  icon="integrations"
                  title={intl.formatMessage({
                    id: "help.quick.connectors",
                    defaultMessage: "Connectors",
                  })}
                  desc={intl.formatMessage({
                    id: "help.quick.connectors.desc",
                    defaultMessage: "Add or manage identity sources and apps.",
                  })}
                  to="/connectors"
                />
              </div>
            </div>

            <div className="help-drawer__section">
              <h3 className="help-drawer__section-title">
                {intl.formatMessage({
                  id: "help.section.faq",
                  defaultMessage: "Common questions",
                })}
              </h3>
              {filteredFAQ.length === 0 ? (
                <p className="help-drawer__empty">
                  {intl.formatMessage({
                    id: "help.search.empty",
                    defaultMessage: "No matching questions. Try a different word or contact support.",
                  })}
                </p>
              ) : (
                <div className="help-drawer__faq">
                  {filteredFAQ.map((item, idx) => (
                    <details className="disclosure" key={idx}>
                      <summary>{item.q}</summary>
                      <p className="muted">{item.a}</p>
                    </details>
                  ))}
                </div>
              )}
            </div>

            <div className="help-drawer__section">
              <h3 className="help-drawer__section-title">
                {intl.formatMessage({
                  id: "help.section.support",
                  defaultMessage: "Get support",
                })}
              </h3>
              <div className="help-drawer__support">
                <a
                  className="help-drawer__support-link"
                  href="mailto:support@shieldnet360.com"
                >
                  <Icon name="email" size={18} />
                  <div>
                    <b>
                      {intl.formatMessage({
                        id: "help.support.email",
                        defaultMessage: "Email support",
                      })}
                    </b>
                    <span className="muted">
                      {intl.formatMessage({
                        id: "help.support.email.desc",
                        defaultMessage: "Reach our team at support@shieldnet360.com. We reply during business hours.",
                      })}
                    </span>
                  </div>
                </a>
                <a
                  className="help-drawer__support-link"
                  href="https://shieldnet360.com/"
                  target="_blank"
                  rel="noreferrer"
                >
                  <Icon name="globe" size={18} />
                  <div>
                    <b>
                      {intl.formatMessage({
                        id: "help.support.website",
                        defaultMessage: "Visit ShieldNet 360",
                      })}
                    </b>
                    <span className="muted">
                      {intl.formatMessage({
                        id: "help.support.website.desc",
                        defaultMessage: "Product guides, videos, and updates on our website.",
                      })}
                    </span>
                  </div>
                </a>
                <a
                  className="help-drawer__support-link"
                  href="https://shieldnet360.com/blog"
                  target="_blank"
                  rel="noreferrer"
                >
                  <Icon name="updates" size={18} />
                  <div>
                    <b>
                      {intl.formatMessage({
                        id: "help.support.updates",
                        defaultMessage: "Product updates",
                      })}
                    </b>
                    <span className="muted">
                      {intl.formatMessage({
                        id: "help.support.updates.desc",
                        defaultMessage: "See what's new in ShieldNet Access and the rest of the platform.",
                      })}
                    </span>
                  </div>
                </a>
              </div>
            </div>
          </div>
        ) : (
          <div className="help-drawer__body help-drawer__body--chat">
            <HelpAssistant />
          </div>
        )}
      </div>
    </div>
  );
}

function QuickAction({
  icon,
  title,
  desc,
  to,
}: {
  icon: IconName;
  title: string;
  desc: string;
  to: string;
}) {
  return (
    <Link to={to} className="help-drawer__action">
      <Icon name={icon} size={18} />
      <div className="help-drawer__action-main">
        <b>{title}</b>
        <span className="muted">{desc}</span>
      </div>
    </Link>
  );
}

type Message = { role: "user" | "assistant"; text: ReactNode };

function HelpAssistant() {
  const intl = useIntl();
  const [input, setInput] = useState("");
  const [messages, setMessages] = useState<Message[]>([
    {
      role: "assistant",
      text: intl.formatMessage({
        id: "help.chat.greeting",
        defaultMessage: "Hi — I'm the ShieldNet Access assistant. I can answer questions about policies, requests, connectors, and getting started. For account-specific issues, contact support.",
      }),
    },
  ]);
  const [busy, setBusy] = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const send = useCallback(() => {
    const text = input.trim();
    if (!text || busy) return;
    setInput("");
    setMessages((prev) => [...prev, { role: "user", text }]);
    setBusy(true);
    // Simulate a brief typing delay for a natural feel.
    window.setTimeout(() => {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", text: answerFor(text, intl) },
      ]);
      setBusy(false);
    }, 400);
  }, [input, busy, intl]);

  return (
    <div className="help-assistant">
      <div className="help-assistant__messages">
        {messages.map((m, idx) => (
          <div
            key={idx}
            className={`help-assistant__message help-assistant__message--${m.role}`}
          >
            {m.text}
          </div>
        ))}
        {busy && (
          <div className="help-assistant__message help-assistant__message--assistant help-assistant__typing">
            <span />
            <span />
            <span />
          </div>
        )}
        <div ref={bottomRef} />
      </div>
      <div className="help-assistant__input">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && send()}
          placeholder={intl.formatMessage({
            id: "help.chat.placeholder",
            defaultMessage: "Ask a question about ShieldNet Access…",
          })}
          disabled={busy}
        />
        <button
          type="button"
          className="btn btn--primary"
          onClick={send}
          disabled={busy || !input.trim()}
        >
          <Icon name="send" size={16} />
        </button>
      </div>
      <p className="help-assistant__disclaimer">
        {intl.formatMessage({
          id: "help.chat.disclaimer",
          defaultMessage: "The assistant answers using product guidance. For account-specific issues, contact support.",
        })}
      </p>
    </div>
  );
}

function answerFor(text: string, intl: IntlShape): ReactNode {
  const lower = text.toLowerCase();

  if (lower.includes("policy") || lower.includes("rule") || lower.includes("policies")) {
    return intl.formatMessage({
      id: "help.chat.answer.policy",
      defaultMessage:
        "Access policies are rules that decide who can reach what. You can write a draft, simulate it safely, then promote it to start enforcing. Go to Policies to create one.",
    });
  }
  if (lower.includes("connector") || lower.includes("source") || lower.includes("connect")) {
    return intl.formatMessage({
      id: "help.chat.answer.connector",
      defaultMessage:
        "Connectors link ShieldNet Access to your identity providers and apps (Google, Microsoft Entra, AWS, etc.). Once connected, your policies can target real users and resources.",
    });
  }
  if (lower.includes("request") || lower.includes("access") || lower.includes("approval")) {
    return intl.formatMessage({
      id: "help.chat.answer.request",
      defaultMessage:
        "Request access from the Your access page or the Access requests list. Low-risk requests may be auto-approved; others go to a reviewer. You'll see status updates in real time.",
    });
  }
  if (lower.includes("score") || lower.includes("health") || lower.includes("dashboard")) {
    return intl.formatMessage({
      id: "help.chat.answer.score",
      defaultMessage:
        "Your dashboard health score starts at 100 and drops for untested drafts, open requests, orphan accounts, or missing connectors. Fix any highlighted item to raise it.",
    });
  }
  if (lower.includes("jit") || lower.includes("just-in-time") || lower.includes("lease")) {
    return intl.formatMessage({
      id: "help.chat.answer.jit",
      defaultMessage:
        "Just-in-time access means you request privilege only when you need it, for a limited time. It's safer than standing admin access.",
    });
  }
  if (lower.includes("pam") || lower.includes("privileged")) {
    return intl.formatMessage({
      id: "help.chat.answer.pam",
      defaultMessage:
        "Privileged access covers servers, databases, and other sensitive systems. Use Targets, Leases, Sessions, and Recordings to manage and audit that access.",
    });
  }
  if (lower.includes("hello") || lower.includes("hi")) {
    return intl.formatMessage({
      id: "help.chat.answer.greeting",
      defaultMessage:
        "Hello! Ask me about policies, connectors, requests, the health score, or just-in-time access.",
    });
  }
  return intl.formatMessage({
    id: "help.chat.answer.fallback",
    defaultMessage:
      "I'm not sure about that one. Try asking about policies, connectors, access requests, or the dashboard health score. For account-specific help, email support@shieldnet360.com.",
  });
}

