import React from "react";

export function TestimonialsSection() {
  const testimonialsRow1 = [
    {
      initials: "AK",
      name: "Abhishek Kulkarni",
      role: "Lead SOC Analyst, Sovereign Cyber Defense",
      colorBg: "bg-indigo-100",
      colorText: "text-indigo-600",
      quote:
        "Raven gave our SOC team immediate passive visibility into stealth STARTTLS stripping attacks that our boundary firewalls completely missed. Zero packets sent to external targets.",
    },
    {
      initials: "VM",
      name: "Vikram Malhotra",
      role: "Digital Forensics & Incident Response (DFIR)",
      colorBg: "bg-emerald-100",
      colorText: "text-emerald-600",
      quote:
        "The court-grade evidence chain linking each security finding to the exact packet offset, byte range, and hash signature makes compliance auditing completely unassailable.",
    },
    {
      initials: "SN",
      name: "Sneha Nair",
      role: "Enterprise Infrastructure & Mail Architect",
      colorBg: "bg-rose-100",
      colorText: "text-rose-600",
      quote:
        "The Cross-Hop Delivery Graph immediately highlighted that our secondary fallback MX had quietly disabled TLS 1.3. We fixed it with the copy-paste Postfix playbook in 5 minutes.",
    },
    {
      initials: "RD",
      name: "Rohan Deshmukh",
      role: "Security Compliance Auditor",
      colorBg: "bg-amber-100",
      colorText: "text-amber-600",
      quote:
        "The deterministic RFC and NIST scoring rubric with honest confidence intervals is refreshing. It tells us exactly what was unobservable instead of handing out false all-clears.",
    },
  ];

  const testimonialsRow2 = [
    ...testimonialsRow1.slice().reverse(),
  ];

  const fullRow1 = [...testimonialsRow1, ...testimonialsRow1];
  const fullRow2 = [...testimonialsRow2, ...testimonialsRow2];

  return (
    <section className="bg-surface-soft py-14 md:py-26">
      <div className="mx-auto max-w-7xl px-6">
        <div className="flex flex-col items-center">
          <h2 className="mt-7 max-w-2xl text-center text-[40px] font-semibold leading-[1.1] tracking-[-0.03em] text-heading md:text-6xl">
            Validated by <span className="text-primary">Security Teams</span>
            <br className="hidden md:block" /> & Forensics Leads
          </h2>
        </div>
      </div>

      <div className="mt-16 flex flex-col gap-6">
        {/* Row 1 Marquee */}
        <div
          className="relative overflow-hidden"
          style={{
            maskImage:
              "linear-gradient(to right, transparent 0%, black 6%, black 94%, transparent 100%)",
            WebkitMaskImage:
              "linear-gradient(to right, transparent 0%, black 6%, black 94%, transparent 100%)",
          }}
        >
          <div className="flex w-max gap-6 animate-marquee hover:[animation-play-state:paused]">
            {fullRow1.map((item, idx) => (
              <div
                key={idx}
                className="flex w-[420px] shrink-0 flex-col rounded-2xl border border-border bg-white p-6 shadow-[0_2px_8px_-4px_rgba(12,12,12,0.04)]"
              >
                <div className="flex items-center gap-3">
                  <span
                    className={`flex h-11 w-11 items-center justify-center rounded-full text-sm font-semibold ${item.colorBg} ${item.colorText}`}
                  >
                    {item.initials}
                  </span>
                  <div className="leading-tight">
                    <p className="text-base font-semibold text-heading">
                      {item.name}
                    </p>
                    <p className="mt-0.5 text-sm text-muted">{item.role}</p>
                  </div>
                </div>
                <div className="my-5 h-px bg-border" />
                <p className="text-sm leading-relaxed text-body">
                  &ldquo;{item.quote}&rdquo;
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* Row 2 Reverse Marquee */}
        <div
          className="relative overflow-hidden"
          style={{
            maskImage:
              "linear-gradient(to right, transparent 0%, black 6%, black 94%, transparent 100%)",
            WebkitMaskImage:
              "linear-gradient(to right, transparent 0%, black 6%, black 94%, transparent 100%)",
          }}
        >
          <div className="flex w-max gap-6 animate-marquee hover:[animation-play-state:paused] [animation-direction:reverse]">
            {fullRow2.map((item, idx) => (
              <div
                key={idx}
                className="flex w-[420px] shrink-0 flex-col rounded-2xl border border-border bg-white p-6 shadow-[0_2px_8px_-4px_rgba(12,12,12,0.04)]"
              >
                <div className="flex items-center gap-3">
                  <span
                    className={`flex h-11 w-11 items-center justify-center rounded-full text-sm font-semibold ${item.colorBg} ${item.colorText}`}
                  >
                    {item.initials}
                  </span>
                  <div className="leading-tight">
                    <p className="text-base font-semibold text-heading">
                      {item.name}
                    </p>
                    <p className="mt-0.5 text-sm text-muted">{item.role}</p>
                  </div>
                </div>
                <div className="my-5 h-px bg-border" />
                <p className="text-sm leading-relaxed text-body">
                  &ldquo;{item.quote}&rdquo;
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
