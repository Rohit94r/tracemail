import React from "react";
import Image from "next/image";

export function FeaturesSection() {
  return (
    <section className="relative overflow-hidden py-14 md:py-26" id="capabilities">
      <div className="mx-auto max-w-7xl px-6">
        <div className="flex justify-center">
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
            Core Capabilities
          </span>
        </div>

        <h2 className="mx-auto mt-7 max-w-3xl text-center text-[40px] font-semibold leading-[1.1] tracking-[-0.03em] text-heading md:text-6xl">
          Everything You <span className="text-primary">Need to Audit</span> Mail Cryptographic Posture
        </h2>

        <div className="mt-16 grid gap-6 md:grid-cols-12">
          {/* Card 1: Confidence Bounded Scoring */}
          <div className="min-w-0 md:col-span-7">
            <div className="relative h-full overflow-hidden rounded-2xl p-3">
              <Image
                src="/cards-bg.webp"
                alt=""
                fill
                className="pointer-events-none absolute inset-0 z-0 object-cover"
              />
              <div className="relative z-10 flex h-full flex-col rounded-4xl bg-surface-soft p-8">
                <div className="inline-flex h-14 w-14 items-center justify-center rounded-md border border-primary/50 bg-primary-soft">
                  <svg
                    aria-hidden="true"
                    className="lucide lucide-shield-alert h-6 w-6 text-primary"
                    fill="none"
                    height="24"
                    stroke="currentColor"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    viewBox="0 0 24 24"
                    width="24"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
                    <path d="M12 8v4" />
                    <path d="M12 16h.01" />
                  </svg>
                </div>
                <h3 className="mt-8 text-2xl font-semibold text-heading">
                  0–100 Confidence-Bounded Posture Score
                </h3>
                <p className="mt-2 text-base text-body">
                  Deterministic mathematical scoring engine based on NIST SP 800-52r2 and RFC standards. Raven produces an honest score with statistical confidence bands and explicitly declared blind spots — never a black-box guess.
                </p>

                <div className="mt-6 flex flex-wrap gap-2">
                  <span className="rounded-full border border-border bg-white px-3 py-1 text-xs font-semibold text-heading">
                    RFC/NIST Deterministic
                  </span>
                  <span className="rounded-full border border-border bg-white px-3 py-1 text-xs font-semibold text-heading">
                    Confidence Intervals
                  </span>
                  <span className="rounded-full border border-border bg-white px-3 py-1 text-xs font-semibold text-heading">
                    No Black-Box Hallucinations
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Card 2: Cross-Hop Delivery Graph */}
          <div className="min-w-0 md:col-span-5">
            <div className="relative h-full overflow-hidden rounded-2xl p-3">
              <Image
                src="/cards-bg.webp"
                alt=""
                fill
                className="pointer-events-none absolute inset-0 z-0 object-cover"
              />
              <div className="relative z-10 flex h-full flex-col rounded-4xl bg-surface-soft p-8">
                <div className="inline-flex h-14 w-14 items-center justify-center rounded-md border border-primary/50 bg-primary-soft">
                  <svg
                    aria-hidden="true"
                    className="lucide lucide-git-branch h-6 w-6 text-primary"
                    fill="none"
                    height="24"
                    stroke="currentColor"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    viewBox="0 0 24 24"
                    width="24"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <line x1="6" x2="6" y1="3" y2="15" />
                    <circle cx="18" cy="6" r="3" />
                    <circle cx="6" cy="18" r="3" />
                    <path d="M18 9a9 9 0 0 1-9 9" />
                  </svg>
                </div>
                <h3 className="mt-8 text-2xl font-semibold text-heading">
                  Cross-Hop Delivery Graph
                </h3>
                <p className="mt-2 text-base text-body">
                  Trace the complete journey of your email across every MX hop and relay. Raven calculates traffic-weighted exposure and instantly highlights the single weakest link.
                </p>
                <div className="mt-6 flex flex-wrap gap-2">
                  <span className="rounded-full border border-border bg-white px-3 py-1 text-xs font-semibold text-heading">
                    Hop-by-Hop Mapping
                  </span>
                  <span className="rounded-full border border-border bg-white px-3 py-1 text-xs font-semibold text-heading">
                    Weakest-Link Pinpoint
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Card 3: Downgrade Radar */}
          <div className="min-w-0 md:col-span-4">
            <div className="relative h-full overflow-hidden rounded-2xl p-3">
              <Image
                src="/cards-bg.webp"
                alt=""
                fill
                className="pointer-events-none absolute inset-0 z-0 object-cover"
              />
              <div className="relative z-10 flex h-full flex-col rounded-4xl bg-surface-soft p-8">
                <div className="inline-flex h-14 w-14 items-center justify-center rounded-md border border-primary/50 bg-primary-soft">
                  <svg
                    aria-hidden="true"
                    className="lucide lucide-radar h-6 w-6 text-primary"
                    fill="none"
                    height="24"
                    stroke="currentColor"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    viewBox="0 0 24 24"
                    width="24"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path d="M19.07 4.93A10 10 0 0 0 6.99 3.34" />
                    <path d="M4 6h.01" />
                    <path d="M2.29 9.62A10 10 0 1 0 21.31 8.35" />
                    <path d="M16.24 7.76A6 6 0 1 0 8.23 16.67" />
                    <path d="M12 18h.01" />
                    <path d="M17.99 11.66A6 6 0 0 1 15.77 14.24" />
                    <circle cx="12" cy="12" r="2" />
                    <path d="m13.41 10.59 5.66-5.66" />
                  </svg>
                </div>
                <h3 className="mt-8 text-2xl font-semibold text-heading">
                  Downgrade Radar
                </h3>
                <p className="mt-2 text-base text-body">
                  State-machine analysis of SMTP handshakes to detect active STARTTLS stripping, command injection, and cipher downgrade anomalies before they cause a breach.
                </p>
              </div>
            </div>
          </div>

          {/* Card 4: Forensic Evidence Chains */}
          <div className="min-w-0 md:col-span-8">
            <div className="relative h-full overflow-hidden rounded-2xl p-3">
              <Image
                src="/cards-bg.webp"
                alt=""
                fill
                className="pointer-events-none absolute inset-0 z-0 object-cover"
              />
              <div className="relative z-10 flex h-full flex-col rounded-4xl bg-surface-soft p-8">
                <div className="inline-flex h-14 w-14 items-center justify-center rounded-md border border-primary/50 bg-primary-soft">
                  <svg
                    aria-hidden="true"
                    className="lucide lucide-file-check-2 h-6 w-6 text-primary"
                    fill="none"
                    height="24"
                    stroke="currentColor"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth="2"
                    viewBox="0 0 24 24"
                    width="24"
                    xmlns="http://www.w3.org/2000/svg"
                  >
                    <path d="M4 22h14a2 2 0 0 0 2-2V7.5L14.5 2H6a2 2 0 0 0-2 2v4" />
                    <polyline points="14 2 14 8 20 8" />
                    <path d="m3 15 2 2 4-4" />
                  </svg>
                </div>
                <h3 className="mt-8 text-2xl font-semibold text-heading">
                  Court-Grade Forensic Evidence Chains
                </h3>
                <p className="mt-2 text-base text-body">
                  Every finding links directly to the exact flow timestamp, packet number, byte offset, and TLS record index. Backed by SHA-256 signed evidence chains that stand up in legal, regulatory, and forensic security audits.
                </p>
                <div className="mt-6 flex flex-wrap gap-2">
                  <span className="rounded-full border border-border bg-white px-3 py-1 text-xs font-semibold text-heading">
                    Exact Packet Offsets
                  </span>
                  <span className="rounded-full border border-border bg-white px-3 py-1 text-xs font-semibold text-heading">
                    SHA-256 Manifest
                  </span>
                  <span className="rounded-full border border-border bg-white px-3 py-1 text-xs font-semibold text-heading">
                    Audit-Ready Exports
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Card 5: Enforcement Consistency */}
          <div className="min-w-0 md:col-span-4">
            <div className="rounded-2xl border border-border bg-surface-soft p-8">
              <div className="inline-flex h-12 w-12 items-center justify-center rounded-xl bg-primary-soft text-primary">
                <svg
                  aria-hidden="true"
                  className="lucide lucide-scale h-6 w-6"
                  fill="none"
                  height="24"
                  stroke="currentColor"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  viewBox="0 0 24 24"
                  width="24"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path d="m16 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z" />
                  <path d="m2 16 3-8 3 8c-.87.65-1.92 1-3 1s-2.13-.35-3-1Z" />
                  <path d="M7 21h10" />
                  <path d="M12 3v18" />
                  <path d="M3 7h2c2 0 5-1 7-2 2 1 5 2 7 2h2" />
                </svg>
              </div>
              <h3 className="mt-6 text-xl font-semibold text-heading">
                Claim vs. Reality Audit
              </h3>
              <p className="mt-2 text-sm text-body">
                Compares published DNS policies (MTA-STS, DANE TLSA, TLS-RPT) against real wire traffic. Raven alerts you when an advertised security policy fails in actual transit.
              </p>
            </div>
          </div>

          {/* Card 6: Incident Replay */}
          <div className="min-w-0 md:col-span-4">
            <div className="rounded-2xl border border-border bg-surface-soft p-8">
              <div className="inline-flex h-12 w-12 items-center justify-center rounded-xl bg-primary-soft text-primary">
                <svg
                  aria-hidden="true"
                  className="lucide lucide-play-circle h-6 w-6"
                  fill="none"
                  height="24"
                  stroke="currentColor"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  viewBox="0 0 24 24"
                  width="24"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <circle cx="12" cy="12" r="10" />
                  <polygon points="10 8 16 12 10 16 10 8" />
                </svg>
              </div>
              <h3 className="mt-6 text-xl font-semibold text-heading">
                Interactive Incident Replay
              </h3>
              <p className="mt-2 text-sm text-body">
                Step-by-step forensic animation replaying flagged sessions. Visually inspect when and where negotiation downgraded with exportable WebM evidence recordings.
              </p>
            </div>
          </div>

          {/* Card 7: 100% Air-Gapped */}
          <div className="min-w-0 md:col-span-4">
            <div className="rounded-2xl border border-border bg-surface-soft p-8">
              <div className="inline-flex h-12 w-12 items-center justify-center rounded-xl bg-primary-soft text-primary">
                <svg
                  aria-hidden="true"
                  className="lucide lucide-shield-check h-6 w-6"
                  fill="none"
                  height="24"
                  stroke="currentColor"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  viewBox="0 0 24 24"
                  width="24"
                  xmlns="http://www.w3.org/2000/svg"
                >
                  <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
                  <path d="m9 12 2 2 4-4" />
                </svg>
              </div>
              <h3 className="mt-6 text-xl font-semibold text-heading">
                Air-Gapped & Sovereign Ready
              </h3>
              <p className="mt-2 text-sm text-body">
                Zero external cloud dependencies. Unplug the network cable, upload a PCAP, and run complete forensic evaluations on isolated defense and enterprise workstations.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
