import React from "react";

export function BenefitsSection() {
  const benefits = [
    "100% Passive Analysis — Zero packets sent to mail servers",
    "Air-Gapped Operation — Works with network cable unplugged",
    "Packet-Level Evidence Chains — Exact byte offsets & flow IDs",
    "STARTTLS Stripping Detection — Automated downgrade alerts",
    "Deterministic RFC/NIST Rubric — Transparent, reproducible math",
    "Zero Content Decryption — Email bodies & creds never touched",
    "Cross-Hop Delivery Graph — Pinpoint the weakest mail relay",
    "MTA-STS & DANE Enforcement — Claim vs reality verification",
    "Automated Remediation Playbooks — Copy-paste configs for Postfix & Exim",
    "Tamper-Evident Evidence — Hash-signed manifests for legal audits",
  ];

  return (
    <section className="relative py-14 md:py-26" id="benefits">
      <div className="mx-auto max-w-7xl px-6">
        <div className="grid gap-12 lg:grid-cols-2 lg:items-center lg:gap-16">
          <div>
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
              Defensive Advantages
            </span>
            <h2 className="mt-7 text-[40px] font-semibold leading-[1.05] tracking-[-0.03em] text-heading md:text-6xl">
              Why Security Teams <span className="text-primary">Trust Raven</span>
            </h2>
            <p className="mt-7 max-w-md text-base text-body md:text-lg">
              Designed from first principles to fulfill rigorous defense requirements: non-intrusive observation, transparent math, and courtroom-admissible evidence.
            </p>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            {benefits.map((benefit, idx) => (
              <div
                key={idx}
                className="flex items-center gap-3 rounded-lg border border-border bg-surface-soft px-4 py-3.5"
              >
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary-soft">
                  <svg
                    aria-hidden="true"
                    className="lucide lucide-check h-3.5 w-3.5 text-primary"
                    fill="none"
                    height="24"
                    stroke="currentColor"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="3"
                    viewBox="0 0 24 24"
                    width="24"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path d="M20 6 9 17l-5-5" />
                  </svg>
                </span>
                <span className="text-sm font-medium text-heading">
                  {benefit}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
