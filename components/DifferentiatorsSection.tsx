import React from "react";

export function DifferentiatorsSection() {
  return (
    <section className="relative py-14 md:py-26">
      <div className="mx-auto max-w-7xl px-6">
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
            Why Raven Is Unique
          </span>
          <h2 className="mt-7 text-[40px] font-semibold leading-[1.1] tracking-[-0.03em] text-heading md:text-6xl">
            What Makes Raven <span className="text-primary">Different</span>
          </h2>
        </div>

        <div className="mt-16 grid gap-6 md:grid-cols-12">
          {/* Item 1 */}
          <div className="rounded-2xl border border-border bg-surface-soft p-8 md:col-span-4 md:col-start-5 md:row-start-2">
            <div
              className="flex h-14 w-14 items-center justify-center rounded-full border border-white shadow-[0_10px_24px_-6px_rgba(12,12,12,0.12)]"
              style={{
                background:
                  "radial-gradient(circle at 50% 45%, #eff6ff 0%, #f8fafc 55%, #ffffff 100%)",
              }}
            >
              <svg
                aria-hidden="true"
                className="lucide lucide-eye-off h-6 w-6 text-primary"
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
                <path d="M9.88 9.88a3 3 0 1 0 4.24 4.24" />
                <path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68" />
                <path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61" />
                <line x1="2" x2="22" y1="2" y2="22" />
              </svg>
            </div>
            <h3 className="mt-8 text-2xl font-semibold text-heading">
              Zero Active Probing
            </h3>
            <p className="mt-2 max-w-lg text-base text-body">
              We never knock on servers or send packets. Raven operates as a pure passive observer, safe for covert military and enterprise SOC environments.
            </p>
          </div>

          {/* Item 2 */}
          <div className="rounded-2xl border border-border bg-surface-soft p-8 md:col-span-4 md:col-start-5 md:row-start-1">
            <div
              className="flex h-14 w-14 items-center justify-center rounded-full border border-white shadow-[0_10px_24px_-6px_rgba(12,12,12,0.12)]"
              style={{
                background:
                  "radial-gradient(circle at 50% 45%, #eff6ff 0%, #f8fafc 55%, #ffffff 100%)",
              }}
            >
              <svg
                aria-hidden="true"
                className="lucide lucide-gauge h-6 w-6 text-primary"
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
                <path d="m12 14 4-4" />
                <path d="M3.34 19a10 10 0 1 1 17.32 0" />
              </svg>
            </div>
            <h3 className="mt-8 text-2xl font-semibold text-heading">
              Honest Uncertainty
            </h3>
            <p className="mt-2 max-w-lg text-base text-body">
              When encryption hides details (like encrypted certificates under TLS 1.3), we declare blind spots rather than pretending everything is fine.
            </p>
          </div>

          {/* Item 3 */}
          <div className="rounded-2xl border border-border bg-surface-soft p-8 md:col-span-4 md:col-start-1 md:row-span-2 md:row-start-1">
            <div
              className="flex h-14 w-14 items-center justify-center rounded-full border border-white shadow-[0_10px_24px_-6px_rgba(12,12,12,0.12)]"
              style={{
                background:
                  "radial-gradient(circle at 50% 45%, #eff6ff 0%, #f8fafc 55%, #ffffff 100%)",
              }}
            >
              <svg
                aria-hidden="true"
                className="lucide lucide-file-text h-6 w-6 text-primary"
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
                <path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z" />
                <path d="M14 2v4a2 2 0 0 0 2 2h4" />
                <path d="M10 9H8" />
                <path d="M16 13H8" />
                <path d="M16 17H8" />
              </svg>
            </div>
            <h3 className="mt-8 text-2xl font-semibold text-heading">
              Court-Grade Receipts
            </h3>
            <p className="mt-2 text-base text-body">
              Every score, flag, and finding comes with the exact packet offset, byte range, and hash-signed span. No hunches, no opaque numbers — only audit-admissible proof.
            </p>
          </div>

          {/* Item 4 */}
          <div className="rounded-2xl border border-border bg-surface-soft p-8 md:col-span-4 md:col-start-9 md:row-start-1">
            <div
              className="flex h-14 w-14 items-center justify-center rounded-full border border-white shadow-[0_10px_24px_-6px_rgba(12,12,12,0.12)]"
              style={{
                background:
                  "radial-gradient(circle at 50% 45%, #eff6ff 0%, #f8fafc 55%, #ffffff 100%)",
              }}
            >
              <svg
                aria-hidden="true"
                className="lucide lucide-history h-6 w-6 text-primary"
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
                <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
                <path d="M3 3v5h5" />
                <path d="M12 7v5l4 2" />
              </svg>
            </div>
            <h3 className="mt-8 text-2xl font-semibold text-heading">
              Posture Decay Timeline
            </h3>
            <p className="mt-2 max-w-lg text-base text-body">
              Monitors cryptographic degradation across time windows. Alerts when a relay drifts from Grade A to Grade D before it is compromised.
            </p>
          </div>

          {/* Item 5 */}
          <div className="rounded-2xl border border-border bg-surface-soft p-8 md:col-span-4 md:col-start-9 md:row-start-2">
            <div
              className="flex h-14 w-14 items-center justify-center rounded-full border border-white shadow-[0_10px_24px_-6px_rgba(12,12,12,0.12)]"
              style={{
                background:
                  "radial-gradient(circle at 50% 45%, #eff6ff 0%, #f8fafc 55%, #ffffff 100%)",
              }}
            >
              <svg
                aria-hidden="true"
                className="lucide lucide-hard-drive-download h-6 w-6 text-primary"
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
                <path d="M12 2v10" />
                <path d="m16 8-4 4-4-4" />
                <rect width="20" height="8" x="2" y="14" rx="2" />
                <path d="M6 18h.01" />
                <path d="M10 18h.01" />
              </svg>
            </div>
            <h3 className="mt-8 text-2xl font-semibold text-heading">
              100% Offline & Deterministic
            </h3>
            <p className="mt-2 max-w-lg text-base text-body">
              Run on air-gapped laptops without internet. The exact same PCAP with the same package version produces bit-for-bit identical report checksums.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
