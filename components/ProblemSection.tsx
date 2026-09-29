import React from "react";
import Image from "next/image";

export function ProblemSection() {
  return (
    <section className="relative py-14 md:py-26" id="problem">
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
              The Real Problem
            </span>
            <h2 className="mt-7 text-[40px] font-semibold leading-[1.05] tracking-[-0.03em] text-heading md:text-6xl">
              Why Email Transit Security is{" "}
              <span className="text-primary">Broken in the Wild</span>
            </h2>
            <p className="mt-7 max-w-lg text-base text-body md:text-lg">
              The Internet was built ~50 years ago where email was designed as an open postcard. Sealing the envelope via STARTTLS is purely voluntary — and in the wild, active attackers silently strip the seal without your knowledge.
            </p>
          </div>

          <div className="relative overflow-hidden rounded-2xl">
            <Image
              src="/cards-bg.webp"
              alt=""
              fill
              className="pointer-events-none absolute inset-0 z-0 object-cover"
            />
            <div className="relative z-10 m-3 rounded-[28px] bg-surface-soft p-8 md:p-10">
              <div className="flex flex-col items-center">
                <div className="text-[120px] font-semibold leading-none tracking-[-0.04em] text-primary md:text-[180px]">
                  30%
                </div>
                <p className="mt-4 max-w-xs text-center text-base font-medium text-heading">
                  of global mail servers present invalid or expired X.509 identity certificates
                </p>
              </div>

              <div className="mt-10 grid grid-cols-2 gap-4">
                <div className="rounded-xl border border-border bg-white p-5 text-center">
                  <div className="flex justify-center">
                    <svg
                      aria-hidden="true"
                      className="lucide lucide-shield-off h-8 w-8 text-muted"
                      fill="none"
                      height="24"
                      stroke="currentColor"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth="1.75"
                      viewBox="0 0 24 24"
                      width="24"
                      xmlns="http://www.w3.org/2000/svg"
                    >
                      <path d="m2 2 20 20" />
                      <path d="M5 5a1 1 0 0 0-1 1v7c0 5 3.5 7.5 7.67 8.94a1 1 0 0 0 .67.01c2.35-.82 4.48-1.97 5.9-3.71" />
                      <path d="M9.309 3.652A12.252 12.252 0 0 0 11.24 2.28a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1v7a9.784 9.784 0 0 1-.08 1.264" />
                    </svg>
                  </div>
                  <p className="mt-3 text-sm font-semibold text-body line-through">
                    Active Port Scanners
                  </p>
                  <p className="mt-1 text-xs text-muted">Intrusive & blocked by firewalls</p>
                </div>

                <div
                  className="rounded-xl border border-border bg-surface-soft p-5 text-center shadow-xs"
                >
                  <div className="flex justify-center">
                    <svg
                      aria-hidden="true"
                      className="lucide lucide-shield-check h-8 w-8 text-primary"
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
                  <p className="mt-3 text-sm font-semibold text-heading">
                    Passive Observation
                  </p>
                  <p className="mt-1 text-xs font-medium text-primary">
                    100% Non-intrusive & silent
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="relative mt-16 overflow-hidden rounded-2xl md:mt-20">
          <Image
            src="/cards-bg.webp"
            alt=""
            fill
            className="pointer-events-none absolute inset-0 z-0 object-cover"
          />
          <div className="relative z-10 m-3 rounded-[28px] bg-surface-soft p-8 md:p-12">
            <p className="mx-auto max-w-2xl text-center text-lg font-semibold text-heading md:text-xl">
              Without passive cryptographic observation, your organization remains blind to
            </p>

            <div className="mt-10 grid gap-8 sm:grid-cols-3 lg:grid-cols-5">
              <div className="flex flex-col items-center gap-4 text-center">
                <span
                  className="flex h-14 w-14 items-center justify-center rounded-2xl border border-white shadow-[0_10px_24px_-6px_rgba(12,12,12,0.12)]"
                  style={{
                    background:
                      "radial-gradient(circle at 50% 45%, #eff6ff 0%, #f8fafc 55%, #ffffff 100%)",
                  }}
                >
                  <svg
                    aria-hidden="true"
                    className="lucide lucide-key-round h-6 w-6 text-primary"
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
                    <path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z" />
                    <circle cx="16.5" cy="7.5" fill="currentColor" r=".5" />
                  </svg>
                </span>
                <p className="text-sm font-semibold text-heading">
                  STARTTLS Stripping Attacks
                </p>
              </div>

              <div className="flex flex-col items-center gap-4 text-center">
                <span
                  className="flex h-14 w-14 items-center justify-center rounded-2xl border border-white shadow-[0_10px_24px_-6px_rgba(12,12,12,0.12)]"
                  style={{
                    background:
                      "radial-gradient(circle at 50% 45%, #eff6ff 0%, #f8fafc 55%, #ffffff 100%)",
                  }}
                >
                  <svg
                    aria-hidden="true"
                    className="lucide lucide-mail-warning h-6 w-6 text-primary"
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
                    <path d="M22 10.5V6a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v12c0 1.1.9 2 2 2h12.5" />
                    <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
                    <path d="M20 14v4" />
                    <path d="M20 22v.01" />
                  </svg>
                </span>
                <p className="text-sm font-semibold text-heading">
                  Handshake Command Injection
                </p>
              </div>

              <div className="flex flex-col items-center gap-4 text-center">
                <span
                  className="flex h-14 w-14 items-center justify-center rounded-2xl border border-white shadow-[0_10px_24px_-6px_rgba(12,12,12,0.12)]"
                  style={{
                    background:
                      "radial-gradient(circle at 50% 45%, #eff6ff 0%, #f8fafc 55%, #ffffff 100%)",
                  }}
                >
                  <svg
                    aria-hidden="true"
                    className="lucide lucide-lock h-6 w-6 text-primary"
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
                    <rect height="11" rx="2" ry="2" width="18" x="3" y="11" />
                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                  </svg>
                </span>
                <p className="text-sm font-semibold text-heading">
                  Silent Plaintext Downgrades
                </p>
              </div>

              <div className="flex flex-col items-center gap-4 text-center">
                <span
                  className="flex h-14 w-14 items-center justify-center rounded-2xl border border-white shadow-[0_10px_24px_-6px_rgba(12,12,12,0.12)]"
                  style={{
                    background:
                      "radial-gradient(circle at 50% 45%, #eff6ff 0%, #f8fafc 55%, #ffffff 100%)",
                  }}
                >
                  <svg
                    aria-hidden="true"
                    className="lucide lucide-database h-6 w-6 text-primary"
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
                    <ellipse cx="12" cy="5" rx="9" ry="3" />
                    <path d="M3 5V19A9 3 0 0 0 21 19V5" />
                    <path d="M3 12A9 3 0 0 0 21 12" />
                  </svg>
                </span>
                <p className="text-sm font-semibold text-heading">
                  Weak Ciphers & Nonce Reuse
                </p>
              </div>

              <div className="flex flex-col items-center gap-4 text-center">
                <span
                  className="flex h-14 w-14 items-center justify-center rounded-2xl border border-white shadow-[0_10px_24px_-6px_rgba(12,12,12,0.12)]"
                  style={{
                    background:
                      "radial-gradient(circle at 50% 45%, #eff6ff 0%, #f8fafc 55%, #ffffff 100%)",
                  }}
                >
                  <svg
                    aria-hidden="true"
                    className="lucide lucide-credit-card h-6 w-6 text-primary"
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
                    <rect height="14" rx="2" width="20" x="2" y="5" />
                    <line x1="2" x2="22" y1="10" y2="10" />
                  </svg>
                </span>
                <p className="text-sm font-semibold text-heading">
                  MTA-STS & DANE Drift
                </p>
              </div>
            </div>

            <div className="mt-10 border-t border-border pt-8 text-center">
              <p className="text-lg font-semibold text-heading md:text-xl">
                SPF, DKIM, and DMARC verify sender identity — they{" "}
                <span className="text-primary">do not guarantee encryption in transit.</span>
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
