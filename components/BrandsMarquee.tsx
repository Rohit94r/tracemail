import React from "react";

export function BrandsMarquee() {
  const mailSystems = [
    {
      name: "Postfix MTA",
      type: "Open Source MTA",
      icon: (
        <svg className="h-6 w-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="2" y="4" width="20" height="16" rx="2" />
          <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
        </svg>
      ),
    },
    {
      name: "Microsoft Exchange",
      type: "Enterprise Mail Server",
      icon: (
        <svg className="h-6 w-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M4 18h9v-12l-5 2v5l-4 2v-8l9 -4l7 2v13l-7 3z" />
        </svg>
      ),
    },
    {
      name: "Exim Mail Server",
      type: "Internet SMTP Server",
      icon: (
        <svg className="h-6 w-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
        </svg>
      ),
    },
    {
      name: "Google Workspace",
      type: "Cloud MX Provider",
      icon: (
        <svg className="h-6 w-6 text-primary" viewBox="0 0 24 24" fill="currentColor">
          <path d="M12.48 10.92v3.28h7.84c-.24 1.84-.853 3.187-1.787 4.133-1.147 1.147-2.933 2.4-6.053 2.4-4.827 0-8.6-3.893-8.6-8.72s3.773-8.72 8.6-8.72c2.6 0 4.507 1.027 5.907 2.347l2.307-2.307C18.747 1.44 16.133 0 12.48 0 5.867 0 .307 5.387.307 12s5.56 12 12.173 12c3.573 0 6.267-1.173 8.373-3.36 2.16-2.16 2.84-5.213 2.84-7.667 0-.76-.053-1.467-.173-2.053H12.48z" />
        </svg>
      ),
    },
    {
      name: "Sendmail",
      type: "Unix Transport Agent",
      icon: (
        <svg className="h-6 w-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polyline points="22 12 16 12 14 15 10 15 8 12 2 12" />
          <path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" />
        </svg>
      ),
    },
    {
      name: "Cisco Secure Email",
      type: "IronPort Gateway",
      icon: (
        <svg className="h-6 w-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      ),
    },
    {
      name: "Proofpoint",
      type: "Enterprise Email Protection",
      icon: (
        <svg className="h-6 w-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10" />
          <path d="m9 12 2 2 4-4" />
        </svg>
      ),
    },
    {
      name: "Mimecast",
      type: "Cloud Gateway Security",
      icon: (
        <svg className="h-6 w-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M2 12h20M12 2v20" />
          <circle cx="12" cy="12" r="6" />
        </svg>
      ),
    },
    {
      name: "Amazon SES",
      type: "Simple Email Service",
      icon: (
        <svg className="h-6 w-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
        </svg>
      ),
    },
    {
      name: "OpenSMTPD",
      type: "Secure BSD Daemon",
      icon: (
        <svg className="h-6 w-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect width="18" height="18" x="3" y="3" rx="2" />
          <path d="m9 9 6 6m0-6-6 6" />
        </svg>
      ),
    },
    {
      name: "ProtonMail Bridge",
      type: "Encrypted Relay",
      icon: (
        <svg className="h-6 w-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect width="18" height="11" x="3" y="11" rx="2" ry="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
      ),
    },
    {
      name: "Zimbra Collaboration",
      type: "Self-Hosted Suite",
      icon: (
        <svg className="h-6 w-6 text-primary" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polygon points="12 2 2 7 12 12 22 7 12 2" />
          <polyline points="2 17 12 22 22 17" />
          <polyline points="2 12 12 17 22 12" />
        </svg>
      ),
    },
  ];

  const fullList = [...mailSystems, ...mailSystems];

  return (
    <section className="relative py-10 md:py-16">
      <p className="text-center text-md font-semibold text-heading">
        Passively verifies cryptographic posture across enterprise MTAs and mail relays
      </p>

      <div
        className="relative mt-10 overflow-hidden"
        style={{
          maskImage:
            "linear-gradient(to right, transparent 0%, black 8%, black 92%, transparent 100%)",
          WebkitMaskImage:
            "linear-gradient(to right, transparent 0%, black 8%, black 92%, transparent 100%)",
        }}
      >
        <div className="flex w-max gap-6 animate-marquee hover:[animation-play-state:paused]">
          {fullList.map((system, idx) => (
            <div
              key={idx}
              className="flex h-[88px] min-w-[240px] items-center justify-start gap-4 rounded-2xl border border-border bg-white px-6 shadow-[0_2px_8px_-4px_rgba(12,12,12,0.04)]"
            >
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-primary-soft">
                {system.icon}
              </div>
              <div className="leading-tight">
                <span className="block text-base font-bold tracking-tight text-heading">
                  {system.name}
                </span>
                <span className="text-xs text-muted font-medium">
                  {system.type}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
