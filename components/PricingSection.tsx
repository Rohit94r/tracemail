"use client";

import React, { useState } from "react";
import Image from "next/image";
import Link from "next/link";
import { Button } from "./Button";

type DeploymentTier = "Community" | "Enterprise" | "Sovereign";

const tierSpecs: Record<
  DeploymentTier,
  { label: string; priceNote: string; badge: string; desc: string }
> = {
  Community: {
    label: "Analyst Workstation",
    priceNote: "Free & Open Source Forever",
    badge: "Air-Gapped Standalone",
    desc: "Single-analyst laptop or incident-response rig. Drag-and-drop PCAP ingest and offline evidence generation.",
  },
  Enterprise: {
    label: "SOC Sensor Grid",
    priceNote: "Self-Hosted Enterprise License",
    badge: "Continuous TAP / SPAN",
    desc: "Network boundary monitoring. Automated folder watch, live WebSocket feed, SIEM export, and posture decay tracking.",
  },
  Sovereign: {
    label: "Defense & Fleet Controller",
    priceNote: "Sovereign Air-Gapped Appliance",
    badge: "Mission-Critical",
    desc: "Designed for CERT-In, defense agencies, and large ISPs. Multi-node batch parsing, court-grade manifests, and sealed air-gapped packaging.",
  },
};

const capabilities = [
  "Deterministic RFC/NIST scoring engine",
  "Packet-level byte offset evidence chains",
  "Cross-hop delivery graph mapping",
  "Downgrade radar & STARTTLS state machine",
  "Zero email content or credential decryption",
  "Tamper-evident SHA-256 report verification",
];

export function PricingSection() {
  const [flows, setFlows] = useState<number>(50);
  const [tier, setTier] = useState<DeploymentTier>("Community");

  const minFlows = 10;
  const maxFlows = 1000;

  const handleFlowsChange = (val: number) => {
    if (isNaN(val)) {
      setFlows(minFlows);
      return;
    }
    const clamped = Math.min(maxFlows, Math.max(minFlows, Math.round(val)));
    setFlows(clamped);
  };

  const progressPercent = ((flows - minFlows) / (maxFlows - minFlows)) * 100;
  const tierIndex = ["Community", "Enterprise", "Sovereign"].indexOf(tier);

  return (
    <section className="relative py-14 md:py-26" id="deployment">
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
            Deployment & Sizing
          </span>
        </div>

        <h2 className="mx-auto mt-7 max-w-3xl text-center text-[40px] font-semibold leading-[1.1] tracking-[-0.03em] text-heading md:text-6xl">
          Self-Hosted <span className="text-primary">Air-Gapped</span> Deployment
        </h2>

        <p className="mx-auto mt-6 max-w-xl text-center text-base text-body md:text-lg">
          Raven is self-hosted software that runs entirely within your perimeter. No cloud dependencies, no credential handovers, and 100% passive.
        </p>

        <div className="mx-auto mt-16 max-w-3xl">
          <div className="relative overflow-hidden rounded-2xl">
            <Image
              src="/cards-bg.webp"
              alt=""
              fill
              className="pointer-events-none absolute inset-0 z-0 object-cover"
            />
            <div className="relative z-10 m-3 flex flex-col gap-8 rounded-[28px] bg-surface-soft p-4">
              <div className="rounded-2xl bg-white p-8 shadow-[0_2px_8px_-4px_rgba(12,12,12,0.04)]">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-border bg-white">
                      <svg
                        aria-hidden="true"
                        className="lucide lucide-server h-4 w-4 text-heading"
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
                        <rect width="20" height="8" x="2" y="2" rx="2" ry="2" />
                        <rect width="20" height="8" x="2" y="14" rx="2" ry="2" />
                        <line x1="6" x2="6.01" y1="6" y2="6" />
                        <line x1="6" x2="6.01" y1="18" y2="18" />
                      </svg>
                    </span>
                    <div>
                      <h3 className="text-xl font-semibold text-heading">
                        {tierSpecs[tier].label}
                      </h3>
                      <p className="mt-0.5 text-xs text-muted">
                        {tierSpecs[tier].desc}
                      </p>
                    </div>
                  </div>
                  <span className="rounded-pill bg-primary-soft px-3.5 py-1 text-xs font-semibold text-primary">
                    {tierSpecs[tier].badge}
                  </span>
                </div>

                <div className="mt-8">
                  <label className="text-xs font-semibold uppercase tracking-wider text-muted block mb-3">
                    Estimated Daily SMTP / IMAP Flows Analyzed
                  </label>
                  <div className="flex items-center gap-3">
                    <button
                      aria-label="Decrease volume"
                      onClick={() => handleFlowsChange(flows - 25)}
                      disabled={flows <= minFlows}
                      className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full border border-border bg-white text-heading transition-colors hover:border-primary hover:text-primary disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-border disabled:hover:text-heading"
                      type="button"
                    >
                      <svg
                        aria-hidden="true"
                        className="lucide lucide-minus h-4 w-4"
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
                        <path d="M5 12h14" />
                      </svg>
                    </button>

                    <input
                      id="flows"
                      type="number"
                      min={minFlows}
                      max={maxFlows}
                      value={flows}
                      onChange={(e) => handleFlowsChange(parseInt(e.target.value, 10))}
                      className="h-11 flex-1 rounded-xl border border-border bg-white px-4 text-center text-lg font-semibold text-heading [appearance:textfield] focus:border-primary focus:outline-none focus:ring-2 focus:ring-primary/15 [&::-webkit-inner-spin-button]:appearance-none [&::-webkit-outer-spin-button]:appearance-none"
                    />

                    <button
                      aria-label="Increase volume"
                      onClick={() => handleFlowsChange(flows + 25)}
                      disabled={flows >= maxFlows}
                      className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full border border-border bg-white text-heading transition-colors hover:border-primary hover:text-primary disabled:cursor-not-allowed disabled:opacity-40 disabled:hover:border-border disabled:hover:text-heading"
                      type="button"
                    >
                      <svg
                        aria-hidden="true"
                        className="lucide lucide-plus h-4 w-4"
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
                        <path d="M5 12h14" />
                        <path d="M12 5v14" />
                      </svg>
                    </button>
                  </div>

                  <div className="mt-5">
                    <input
                      aria-label="Flows slider"
                      type="range"
                      min={minFlows}
                      max={maxFlows}
                      value={flows}
                      onChange={(e) => handleFlowsChange(parseInt(e.target.value, 10))}
                      style={{
                        background: `linear-gradient(to right, var(--color-primary) 0%, var(--color-primary) ${progressPercent}%, var(--color-border) ${progressPercent}%, var(--color-border) 100%)`,
                        height: "8px",
                      }}
                      className="w-full cursor-pointer appearance-none rounded-full"
                    />
                    <div className="mt-3 flex justify-between text-xs text-muted">
                      <span>{minFlows} Flows / Day (Single Server)</span>
                      <span>{maxFlows}+ Flows / Day (Fleet Enterprise)</span>
                    </div>
                  </div>
                </div>

                <div className="my-8 h-px bg-border" />

                <div className="mb-6 flex flex-wrap items-center gap-3">
                  <span className="text-xs font-medium text-muted">
                    Deployment Edition
                  </span>
                  <div className="relative inline-grid grid-cols-3 rounded-full border border-border bg-white p-0.5">
                    <span
                      aria-hidden="true"
                      className="absolute inset-y-0.5 left-0.5 w-[calc((100%-4px)/3)] rounded-full bg-primary transition-transform duration-300 ease-out"
                      style={{
                        transform: `translateX(${tierIndex * 100}%)`,
                      }}
                    />
                    {(["Community", "Enterprise", "Sovereign"] as DeploymentTier[]).map((t) => (
                      <button
                        key={t}
                        aria-pressed={tier === t}
                        onClick={() => setTier(t)}
                        className={`relative z-10 rounded-full px-3 py-1 text-xs font-semibold transition-colors duration-300 ${
                          tier === t
                            ? "text-white"
                            : "text-body hover:text-heading"
                        }`}
                        type="button"
                      >
                        {t}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
                  <div className="flex flex-col gap-1">
                    <div className="flex items-baseline gap-2">
                      <span className="text-2xl md:text-3xl font-semibold leading-tight text-heading">
                        {tierSpecs[tier].priceNote}
                      </span>
                    </div>
                    <p className="text-xs text-muted mt-1">
                      100% self-hosted on your hardware. Zero data ever leaves your perimeter.
                    </p>
                  </div>

                  <div className="flex flex-col items-stretch gap-3 sm:items-end">
                    <div className="flex items-center gap-3">
                      <Link
                        className="rounded-pill border border-primary bg-white px-5 py-2.5 text-sm font-medium text-primary transition-all hover:bg-primary-soft hover:shadow-sm"
                        href="#faq"
                      >
                        Architecture Docs
                      </Link>
                      <Button href="/" size="md">
                        Deploy Raven
                      </Button>
                    </div>
                  </div>
                </div>
              </div>

              <div className="grid gap-x-10 gap-y-5 px-4 pb-2 md:grid-cols-2">
                {capabilities.map((cap) => (
                  <div key={cap} className="flex items-center gap-2.5">
                    <svg
                      aria-hidden="true"
                      className="lucide lucide-check-circle-2 h-4 w-4 text-primary shrink-0"
                      fill="none"
                      height="24"
                      stroke="currentColor"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth="2.25"
                      viewBox="0 0 24 24"
                      width="24"
                      xmlns="http://www.w3.org/2000/svg"
                    >
                      <path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z" />
                      <path d="m9 12 2 2 4-4" />
                    </svg>
                    <span className="text-sm font-medium text-heading">
                      {cap}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
