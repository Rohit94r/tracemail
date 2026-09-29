"use client";

import React from "react";
import Link from "next/link";
import {
  Crosshair,
  AlertTriangle,
  ExternalLink,
} from "lucide-react";

export default function LensPage() {

  const forecasts = [
    {
      id: "FC-01",
      attackClass: "Active BGP Hijack & Cleartext STARTTLS Stripping",
      likelihood: "HIGH",
      confidence: "94% (Observed Downstream Stripping)",
      rationale:
        "Sending MTAs exhibit opportunistic TLS fallback behavior without strict MTA-STS or DANE pinning. Any route announcement hijack will silently harvest full email plaintext without user warning.",
      drivers: [
        { id: "FIND-001", ruleId: "SMS-ENF-002", title: "Active STARTTLS Stripping" },
        { id: "FIND-007", ruleId: "SMS-ENF-001", title: "MTA-STS Policy Absent" },
      ],
      impact: "Total compromise of email confidentiality and credential theft.",
    },
    {
      id: "FC-02",
      attackClass: "Sweet32 Birthday Attack Session Key Recovery",
      likelihood: "MEDIUM",
      confidence: "82% (Legacy 3DES-CBC Negotiated)",
      rationale:
        "Long-lived SMTP connections negotiating 3DES-EDE-CBC are susceptible to collision attacks after approximately 32GB of encrypted ciphertext, revealing plaintext blocks.",
      drivers: [
        { id: "FIND-003", ruleId: "SMS-CIPH-001", title: "Deprecated 3DES Cipher Suite" },
      ],
      impact: "Plaintext exfiltration of encrypted financial attachments.",
    },
    {
      id: "FC-03",
      attackClass: "Adversary Ingress via Hostname Spoofing",
      likelihood: "MEDIUM",
      confidence: "78% (Peer Failed Open on Invalid SAN)",
      rationale:
        "Client MTAs failed open when presented with an invalid certificate SAN. An adversary presenting a valid cert for an arbitrary domain can successfully intercept traffic.",
      drivers: [
        { id: "FIND-004", ruleId: "SMS-X509-002", title: "SAN Hostname Mismatch" },
      ],
      impact: "Silent man-in-the-middle message interception and tampering.",
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="inline-flex items-center gap-1.5 rounded-md bg-slate-100 px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider text-slate-700 mb-2">
          <Crosshair className="h-3.5 w-3.5 text-slate-600" />
          Predictive Attack Lens
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight text-heading">
          Attack Lens & Next-Step Threat Forecasting
        </h1>
        <p className="mt-1 text-sm text-body">
          &quot;What&apos;s most likely next, based on what we see&quot; — mathematically derived extrapolation from observed protocol vulnerabilities.
        </p>
      </div>

      {/* Non-Dismissible Forecast Banner (Strict FR-40 Requirement) */}
      <div className="rounded-2xl border-2 border-amber-400 bg-amber-500/10 p-4 text-xs font-bold text-amber-900 flex items-center gap-3">
        <AlertTriangle className="h-5 w-5 text-amber-600 shrink-0" />
        <span>
          FORECAST, NOT FACT — Evidence-forward extrapolation. Every forecast is mathematically bound to ≥1 observed wire-level finding. Predictions reflect exposure likelihood, not active adversary telemetry.
        </span>
      </div>

      {/* Forecast List */}
      <div className="space-y-4">
        {forecasts.map((fc) => (
          <div
            key={fc.id}
            className="rounded-3xl border border-border bg-white p-6 shadow-xs space-y-4"
          >
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 border-b border-border/60 pb-4">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-slate-400">
                    {fc.id}
                  </span>
                  <h3 className="text-base font-bold text-heading">
                    {fc.attackClass}
                  </h3>
                </div>
                <div className="text-xs text-muted mt-0.5">
                  Confidence: <strong className="text-slate-800">{fc.confidence}</strong>
                </div>
              </div>

              <span
                className={`rounded-xl px-3 py-1 text-xs font-extrabold tracking-wider uppercase ${
                  fc.likelihood === "HIGH"
                    ? "bg-red-100 text-red-700 border border-red-300"
                    : "bg-amber-100 text-amber-700 border border-amber-300"
                }`}
              >
                {fc.likelihood} LIKELIHOOD
              </span>
            </div>

            <p className="text-xs text-slate-700 leading-relaxed">
              {fc.rationale}
            </p>

            {/* Drivers & Evidence Links */}
            <div className="rounded-2xl border border-border bg-surface-soft p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1">
                  Driving Observed Wire Findings:
                </span>
                <div className="flex flex-wrap gap-2">
                  {fc.drivers.map((d) => (
                    <Link
                      key={d.id}
                      href={`/dashboard/findings?id=${d.ruleId}`}
                      className="inline-flex items-center gap-1.5 rounded-lg bg-white border border-border px-2.5 py-1 text-xs font-semibold text-slate-800 hover:border-primary hover:text-primary transition-colors shadow-xs"
                    >
                      <span className="font-mono text-primary font-bold">{d.ruleId}</span>
                      <span>{d.title}</span>
                      <ExternalLink className="h-3 w-3 text-slate-400" />
                    </Link>
                  ))}
                </div>
              </div>

              <div className="text-right shrink-0">
                <span className="text-[11px] text-muted block">Projected Impact:</span>
                <span className="text-xs font-semibold text-red-600">{fc.impact}</span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
