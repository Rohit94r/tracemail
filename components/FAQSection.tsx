import React from "react";
import { Button } from "./Button";

export function FAQSection() {
  const faqs = [
    {
      q: "What is Raven and how does it work?",
      a: "Raven is a passive cryptographic posture assessment platform for email infrastructure. It analyzes passively captured SMTP, IMAP, and POP3 traffic (from PCAP files or network TAP/SPAN ports) to evaluate TLS negotiation, certificate integrity, and downgrade vulnerabilities without sending a single packet.",
    },
    {
      q: "Does Raven connect to our mail servers or read email contents?",
      a: "Never. Raven is self-hosted software installed on your own infrastructure. It requires zero mail passwords, never logs into mailboxes, and never touches email bodies or attachments. It inspects only boundary handshake metadata, cipher suites, X.509 certs, and DNS policies.",
    },
    {
      q: "Why is passive observation better than active scanning?",
      a: "Active scanners knock on doors from outside, generating loud firewall alerts and failing to reflect actual end-to-end delivery behavior. Active tools cannot observe active TLS stripping happening between relays in the wild. Raven passively watches the authentic traffic flow with zero network noise.",
    },
    {
      q: "Can Raven operate in air-gapped or classified environments?",
      a: "Yes. Raven was engineered specifically for air-gapped, zero-internet sovereign environments. All scoring rubrics, cipher intelligence, and reporting engines run completely locally. The entire flow from PCAP upload to signed PDF report works with the network cable unplugged.",
    },
    {
      q: "What makes Raven's posture score trustworthy?",
      a: "Most security tools produce opaque numbers without receipts. Raven's 0–100 score is deterministic, mathematical, and mapped directly to NIST SP 800-52r2 and RFC standards. It provides statistical confidence intervals and explicitly declares unobservable metadata rather than assuming it is clean.",
    },
    {
      q: "How does Raven detect STARTTLS stripping and downgrade attacks?",
      a: "Raven incorporates a 6-class STARTTLS state machine that tracks the exact negotiation flow between sender and receiver. It detects when an intermediary strips STARTTLS announcements, injects commands, or forces fallback to unencrypted plaintext.",
    },
  ];

  return (
    <section className="py-14 md:py-26" id="faq">
      <div className="mx-auto max-w-7xl px-6">
        <div className="grid gap-12 md:grid-cols-12 md:gap-16">
          <div className="md:col-span-5">
            <span className="inline-flex items-center gap-2 rounded-pill bg-primary-soft px-4 py-1.5 text-xs font-bold uppercase tracking-[0.14em] text-primary">
              <svg
                aria-hidden="true"
                className="lucide lucide-sparkles h-3.5 w-3.5"
                fill="none"
                height="24"
                stroke="currentColor"
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2.5"
                viewBox="0 0 24 24"
                width="24"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path d="M11.017 2.814a1 1 0 0 1 1.966 0l1.051 5.558a2 2 0 0 0 1.594 1.594l5.558 1.051a1 1 0 0 1 0 1.966l-5.558 1.051a2 2 0 0 0-1.594 1.594l-1.051 5.558a1 1 0 0 1-1.966 0l-1.051-5.558a2 2 0 0 0-1.594-1.594l-5.558-1.051a1 1 0 0 1 0-1.966l5.558-1.051a2 2 0 0 0 1.594-1.594z" />
                <path d="M20 2v4" />
                <path d="M22 4h-4" />
                <circle cx="4" cy="20" r="2" />
              </svg>
              FAQ
            </span>

            <h2 className="mt-7 text-[40px] font-semibold leading-[1.1] tracking-[-0.03em] text-heading md:text-6xl">
              Frequently Asked
              <br />
              <span className="text-primary">Questions</span>
            </h2>

            <p className="mt-6 max-w-md text-base text-body">
              Everything you need to know about Raven&apos;s passive observation principles, cryptographic methodology, and air-gapped deployment.
            </p>

            <div className="mt-10">
              <Button href="#deployment" size="lg">
                Deploy Raven
              </Button>
            </div>
          </div>

          <div className="flex flex-col gap-4 md:col-span-7">
            {faqs.map((faq, idx) => (
              <details
                key={idx}
                open={idx === 0}
                className="group/faq overflow-hidden rounded-2xl border border-border bg-white transition-all duration-200 open:border-primary/40 open:shadow-sm"
              >
                <summary className="flex cursor-pointer items-center justify-between p-6 text-left text-lg font-semibold text-heading transition-colors hover:text-primary">
                  <span>{faq.q}</span>
                  <span className="ml-4 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-surface-soft text-heading transition-transform duration-200 group-open/faq:rotate-180 group-open/faq:bg-primary-soft group-open/faq:text-primary">
                    <svg
                      aria-hidden="true"
                      className="lucide lucide-chevron-down h-4 w-4"
                      fill="none"
                      height="24"
                      stroke="currentColor"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth="2.5"
                      viewBox="0 0 24 24"
                      width="24"
                      xmlns="http://www.w3.org/2000/svg"
                    >
                      <path d="m6 9 6 6 6-6" />
                    </svg>
                  </span>
                </summary>
                <div className="px-6 pb-6 pt-1 text-base leading-relaxed text-body border-t border-border/50 mt-1">
                  {faq.a}
                </div>
              </details>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
