import React from "react";
import Image from "next/image";

export function BlogSection() {
  const articles = [
    {
      title: "The Anatomy of STARTTLS Stripping in Enterprise Mail Flows",
      desc: "How adversaries exploit voluntary opportunistic encryption, bypass unverified certificates, and silently downgrade email transit security in the wild.",
      readTime: "5 Min Read",
      category: "Threat Research",
      views: "1.2k views",
      href: "#research",
      image: "/blog-starttls-stripping.svg",
    },
    {
      title: "Why 30% of Global Mail Server Certificates Fail Validation",
      desc: "A deep dive into hostname mismatches, expired trust chains, and why over half of modern MTAs never validate peer identity certificates.",
      readTime: "6 Min Read",
      category: "Cryptographic Audit",
      views: "850 views",
      href: "#research",
      image: "/blog-cert-validation.svg",
    },
    {
      title: "Enforcing MTA-STS and DANE: The Missing Defense Layer",
      desc: "Why SPF, DKIM, and DMARC are not enough to protect transit confidentiality, and how cryptographic pinning eliminates active downgrade risks.",
      readTime: "4 Min Read",
      category: "Protocol Standards",
      views: "940 views",
      href: "#research",
      image: "/blog-mtasts-dane.svg",
    },
  ];

  return (
    <section className="py-14 md:py-26" id="research">
      <div className="mx-auto max-w-7xl px-6">
        <div className="flex flex-col items-center">
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
            Research & Intelligence
          </span>
          <h2 className="mt-7 max-w-3xl text-center text-[40px] font-semibold leading-[1.1] tracking-[-0.03em] text-heading md:text-6xl">
            Stay Ahead with Cryptographic
            <br className="hidden md:block" /> Email{" "}
            <span className="text-primary">Insights</span>
          </h2>
        </div>

        <div className="mt-16 grid gap-6 md:grid-cols-3">
          {articles.map((item, idx) => (
            <a
              key={idx}
              className="group flex flex-col rounded-3xl border border-transparent bg-surface-soft p-3 transition-colors duration-200 hover:border-primary"
              href={item.href}
            >
              <div className="relative aspect-[16/10] overflow-hidden rounded-2xl bg-primary-soft">
                <Image
                  src={item.image}
                  alt={item.title}
                  fill
                  className="object-cover transition-transform duration-500 group-hover:scale-[1.03]"
                />
                <span className="absolute left-3 top-3 rounded-full bg-white/90 backdrop-blur-sm px-3 py-1 text-xs font-semibold text-primary">
                  {item.category}
                </span>
              </div>

              <div className="flex flex-1 flex-col p-5">
                <h3 className="text-xl font-semibold leading-tight text-heading">
                  {item.title}
                </h3>
                <p className="mt-3 text-sm leading-relaxed text-body">
                  {item.desc}
                </p>

                <div className="mt-6 h-px bg-border" />

                <div className="mt-5 flex items-center justify-between">
                  <span className="text-sm text-body">
                    • {item.readTime} · {item.views}
                  </span>
                  <span className="flex h-9 w-9 items-center justify-center rounded-full bg-primary text-white transition-transform group-hover:scale-110">
                    <svg
                      aria-hidden="true"
                      className="lucide lucide-arrow-up-right h-4 w-4"
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
                      <path d="M7 7h10v10" />
                      <path d="M7 17 17 7" />
                    </svg>
                  </span>
                </div>
              </div>
            </a>
          ))}
        </div>
      </div>
    </section>
  );
}
