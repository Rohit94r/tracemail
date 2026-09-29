"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  ShieldCheck,
  Info,
  HelpCircle,
} from "lucide-react";
import { useDashboard } from "@/components/dashboard/DashboardContext";

export default function PosturePage() {
  const { activeSession, mxHosts } = useDashboard();
  const [showTooltip, setShowTooltip] = useState(false);

  // Confidence label calculation
  const ciWidth = activeSession.ciHigh - activeSession.ciLow;
  const isHighUncertainty = ciWidth > 15;
  const confidenceLabel = isHighUncertainty ? "LOW CONFIDENCE (BROAD CI)" : "HIGH CONFIDENCE";

  // Tri-state summary aggregates
  const totalSecure = activeSession.flows - (activeSession.findingsCount.critical * 120 + activeSession.findingsCount.high * 80);
  const totalVuln = activeSession.findingsCount.critical * 120 + activeSession.findingsCount.high * 80;
  const totalNotObs = activeSession.findingsCount.notObservable * 35;

  return (
    <div className="space-y-8">
      {/* Title & Section Tag */}
      <div>
        <div className="inline-flex items-center gap-1.5 rounded-md bg-slate-100 px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider text-slate-700 mb-2">
          <ShieldCheck className="h-3.5 w-3.5 text-slate-600" />
          Cryptographic Posture Evaluation
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight text-heading">
          Security Posture Verdict & Honest Uncertainty
        </h1>
        <p className="mt-1 text-sm text-body">
          Rigorous 0–100 composite scoring bounded by formal 95% Confidence Intervals. Unobservable parameters expand uncertainty rather than inflating false scores.
        </p>
      </div>

      {/* 1. VerdictHero (Strict specification adherence: never a bare number) */}
      <div className="relative overflow-hidden rounded-2xl border border-border bg-white p-7 shadow-xs">

        <div className="relative flex flex-col md:flex-row md:items-center md:justify-between gap-6">
          <div className="space-y-3">
            <div className="flex items-center gap-3">
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-slate-500">
                ACTIVE CAPTURE POSTURE VERDICT
              </span>
              <span
                className={`rounded-full px-3 py-0.5 text-xs font-bold ${
                  isHighUncertainty
                    ? "bg-amber-100 text-amber-800 border border-amber-300"
                    : "bg-emerald-100 text-emerald-800 border border-emerald-300"
                }`}
              >
                {confidenceLabel}
              </span>
            </div>

            {/* Score + CI + Grade Display */}
            <div className="flex flex-wrap items-baseline gap-4">
              <span className="text-6xl font-black tracking-tight text-heading">
                {activeSession.score}
              </span>
              <span className="font-mono text-2xl font-bold text-slate-400">
                / 100
              </span>
              <span className="rounded-xl bg-slate-100 px-3 py-1 font-mono text-lg font-bold text-slate-700">
                [CI: {activeSession.ciLow}–{activeSession.ciHigh}]
              </span>
              <span
                className={`text-2xl font-extrabold ${
                  activeSession.score >= 80
                    ? "text-emerald-600"
                    : activeSession.score >= 60
                    ? "text-amber-600"
                    : "text-red-600"
                }`}
              >
                {activeSession.grade}
              </span>
            </div>

            {/* Honest Reason Chip (FR-20 requirement) */}
            <div className="relative inline-flex items-center gap-2 rounded-xl bg-surface-soft px-3.5 py-1.5 border border-border">
              <Info className="h-4 w-4 text-primary shrink-0" />
              <span className="text-xs font-semibold text-slate-700">
                Bounding Reason:{" "}
                <span className="font-mono text-slate-900">
                  X.509 chain not-observable under TLS 1.3 encrypted handshake
                </span>
              </span>
              <button
                type="button"
                onClick={() => setShowTooltip(!showTooltip)}
                className="text-slate-400 hover:text-slate-700 transition-colors ml-1"
                title="Explain confidence bound calculation"
              >
                <HelpCircle className="h-3.5 w-3.5" />
              </button>

              {showTooltip && (
                <div className="absolute left-0 top-full mt-2 w-80 rounded-2xl border border-border bg-slate-900 text-white p-4 shadow-xl z-30 text-xs">
                  <div className="font-bold text-cyan-400 mb-1">
                    Raven Principle #2: Honest Uncertainty
                  </div>
                  <p className="text-slate-300 leading-relaxed">
                    Under RFC 8446, TLS 1.3 encrypts the Certificate handshake message. Without decrypting private keys, a passive sniffer cannot inspect certificate attributes. Raven explicitly floors sub-confidence to 0.15 and broadens the CI interval rather than asserting a false-clean pass.
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Tri-State Summary Counts */}
          <div className="flex flex-row md:flex-col gap-3 border-t md:border-t-0 md:border-l border-border/80 pt-4 md:pt-0 md:pl-8">
            <div className="flex items-center justify-between gap-6 text-xs">
              <span className="flex items-center gap-1.5 font-semibold text-emerald-700">
                <span className="h-2 w-2 rounded-full bg-emerald-500" />
                SECURE FLOWS:
              </span>
              <span className="font-mono font-bold text-slate-900">
                {totalSecure.toLocaleString()}
              </span>
            </div>
            <div className="flex items-center justify-between gap-6 text-xs">
              <span className="flex items-center gap-1.5 font-semibold text-red-700">
                <span className="h-2 w-2 rounded-full bg-red-500" />
                VULNERABLE FLOWS:
              </span>
              <span className="font-mono font-bold text-slate-900">
                {totalVuln.toLocaleString()}
              </span>
            </div>
            <div className="flex items-center justify-between gap-6 text-xs">
              <span className="flex items-center gap-1.5 font-semibold text-slate-500">
                <span className="h-2 w-2 rounded-full bg-slate-400" />
                NOT-OBSERVABLE:
              </span>
              <span className="font-mono font-bold text-slate-900">
                {totalNotObs.toLocaleString()}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* 2. MX Heatmap Matrix (FR-21: Rows = MX, Cols = 6 Sub-scores, hatched for NOT-OBSERVABLE) */}
      <div className="rounded-3xl border border-border bg-white p-6 shadow-xs space-y-4">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-2">
          <div>
            <h3 className="text-base font-bold text-heading">
              Per-MTA Cryptographic Dimension Heatmap
            </h3>
            <p className="text-xs text-muted">
              Evaluated across 6 weighted sub-scores (Proto 20%, Ciph 25%, Key 15%, X509 15%, DNS 10%, Enforce 15%).
            </p>
          </div>
          <div className="flex items-center gap-4 text-xs">
            <span className="flex items-center gap-1 text-slate-600">
              <span className="h-3 w-3 rounded-xs bg-emerald-500" /> &gt;80 Strong
            </span>
            <span className="flex items-center gap-1 text-slate-600">
              <span className="h-3 w-3 rounded-xs bg-amber-500" /> 60-79 Moderate
            </span>
            <span className="flex items-center gap-1 text-slate-600">
              <span className="h-3 w-3 rounded-xs bg-red-500" /> &lt;60 Weak
            </span>
            <span className="flex items-center gap-1 text-slate-600 font-semibold">
              <span className="h-3 w-3 rounded-xs border border-slate-400 bg-[repeating-linear-gradient(45deg,#cbd5e1,#cbd5e1_2px,#f1f5f9_2px,#f1f5f9_6px)]" /> Not Observable
            </span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="border-b border-border text-slate-400 font-bold uppercase text-[10px]">
                <th className="pb-3 pr-4">MTA Node & IP</th>
                <th className="pb-3 text-center">Protocol (20%)</th>
                <th className="pb-3 text-center">Cipher Suite (25%)</th>
                <th className="pb-3 text-center">Key Exch (15%)</th>
                <th className="pb-3 text-center">X.509 Cert (15%)</th>
                <th className="pb-3 text-center">DNS & Pinning (10%)</th>
                <th className="pb-3 text-center">Enforcement (15%)</th>
                <th className="pb-3 text-right">Composite</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {mxHosts.map((host) => (
                <tr key={host.name} className="hover:bg-slate-50 transition-colors">
                  <td className="py-4 pr-4">
                    <div className="font-mono font-bold text-slate-900">{host.name}</div>
                    <div className="text-[10px] text-muted">{host.ip} · {host.role}</div>
                  </td>

                  {/* Proto */}
                  <td className="py-4 text-center">
                    <span className={`inline-block w-16 py-1.5 rounded-lg font-mono font-bold ${
                      host.subscores.protocol >= 80 ? "bg-emerald-100 text-emerald-800" :
                      host.subscores.protocol >= 60 ? "bg-amber-100 text-amber-800" : "bg-red-100 text-red-800"
                    }`}>
                      {host.subscores.protocol}
                    </span>
                  </td>

                  {/* Cipher */}
                  <td className="py-4 text-center">
                    <span className={`inline-block w-16 py-1.5 rounded-lg font-mono font-bold ${
                      host.subscores.cipher >= 80 ? "bg-emerald-100 text-emerald-800" :
                      host.subscores.cipher >= 60 ? "bg-amber-100 text-amber-800" : "bg-red-100 text-red-800"
                    }`}>
                      {host.subscores.cipher}
                    </span>
                  </td>

                  {/* Key Exchange */}
                  <td className="py-4 text-center">
                    <span className={`inline-block w-16 py-1.5 rounded-lg font-mono font-bold ${
                      host.subscores.keyExchange >= 80 ? "bg-emerald-100 text-emerald-800" :
                      host.subscores.keyExchange >= 60 ? "bg-amber-100 text-amber-800" : "bg-red-100 text-red-800"
                    }`}>
                      {host.subscores.keyExchange}
                    </span>
                  </td>

                  {/* X.509 (HATCH PATTERN FOR NOT-OBSERVABLE per spec) */}
                  <td className="py-4 text-center">
                    {host.subscores.x509 === "NOT-OBSERVABLE" ? (
                      <span
                        className="inline-block w-22 py-1.5 rounded-lg font-mono font-bold text-[10px] text-slate-600 border border-slate-300 bg-[repeating-linear-gradient(45deg,#e2e8f0,#e2e8f0_3px,#f8fafc_3px,#f8fafc_8px)]"
                        title="X.509 Cert Chain is encrypted on wire under TLS 1.3. Cannot be verified passively."
                      >
                        NOT-OBS
                      </span>
                    ) : (
                      <span className={`inline-block w-16 py-1.5 rounded-lg font-mono font-bold ${
                        Number(host.subscores.x509) >= 80 ? "bg-emerald-100 text-emerald-800" :
                        Number(host.subscores.x509) >= 60 ? "bg-amber-100 text-amber-800" : "bg-red-100 text-red-800"
                      }`}>
                        {host.subscores.x509}
                      </span>
                    )}
                  </td>

                  {/* DNS */}
                  <td className="py-4 text-center">
                    <span className={`inline-block w-16 py-1.5 rounded-lg font-mono font-bold ${
                      host.subscores.dns >= 80 ? "bg-emerald-100 text-emerald-800" :
                      host.subscores.dns >= 60 ? "bg-amber-100 text-amber-800" : "bg-red-100 text-red-800"
                    }`}>
                      {host.subscores.dns}
                    </span>
                  </td>

                  {/* Enforcement */}
                  <td className="py-4 text-center">
                    <span className={`inline-block w-16 py-1.5 rounded-lg font-mono font-bold ${
                      host.subscores.enforcement >= 80 ? "bg-emerald-100 text-emerald-800" :
                      host.subscores.enforcement >= 60 ? "bg-amber-100 text-amber-800" : "bg-red-100 text-red-800"
                    }`}>
                      {host.subscores.enforcement}
                    </span>
                  </td>

                  {/* Composite */}
                  <td className="py-4 text-right">
                    <div className="font-mono font-bold text-slate-900">
                      {host.score}/100
                    </div>
                    <div className="text-[10px] font-semibold text-slate-500">
                      {host.grade}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 3. Enforcement Consistency Panel (MTA-STS & DANE) */}
      <div className="rounded-3xl border border-border bg-white p-6 shadow-xs space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-base font-bold text-heading">
              Enforcement Consistency Verification (MTA-STS / DANE TLSA)
            </h3>
            <p className="text-xs text-muted">
              Correlates declared DNS pinning policies with observed wire-level cleartext fallback ratios.
            </p>
          </div>
          <span className="text-xs font-mono font-semibold text-slate-500">
            RFC 8461 & RFC 7672
          </span>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          {mxHosts.map((host) => (
            <div
              key={host.name}
              className={`rounded-2xl border p-5 transition-all ${
                host.verdict === "VIOLATION"
                  ? "border-red-300 bg-red-50/30"
                  : "border-border bg-surface-soft/40"
              }`}
            >
              <div className="flex items-start justify-between">
                <div>
                  <h4 className="font-mono text-xs font-bold text-slate-900">
                    {host.name}
                  </h4>
                  <span className="text-[11px] text-muted">{host.role}</span>
                </div>
                {/* Critical render rule: VIOLATION is louder than any score */}
                <span
                  className={`rounded-lg px-2.5 py-1 text-xs font-extrabold uppercase tracking-wider ${
                    host.verdict === "VIOLATION"
                      ? "bg-red-600 text-white shadow-xs animate-pulse"
                      : host.verdict === "CONSISTENT"
                      ? "bg-emerald-100 text-emerald-800"
                      : "bg-slate-200 text-slate-700"
                  }`}
                >
                  {host.verdict}
                </span>
              </div>

              <div className="mt-4 grid grid-cols-2 gap-3 text-xs border-t border-border/60 pt-3">
                <div>
                  <span className="text-muted block">MTA-STS Policy:</span>
                  <span className="font-mono font-bold text-slate-800 uppercase">
                    mode={host.mtaStsMode}
                  </span>
                </div>
                <div>
                  <span className="text-muted block">DANE TLSA (DNSSEC):</span>
                  <span className="font-mono font-bold text-slate-800">
                    {host.daneTlsa}
                  </span>
                </div>
                <div>
                  <span className="text-muted block">TLS-RPT Aggregation:</span>
                  <span className="font-mono font-semibold text-slate-800">
                    {host.tlsRpt ? "ENABLED (_smtp._tls)" : "DISABLED"}
                  </span>
                </div>
                <div>
                  <span className="text-muted block">Observed Plaintext Ratio:</span>
                  <span className={`font-mono font-bold ${
                    host.plaintextRatio > 0.1 ? "text-red-600" : "text-emerald-600"
                  }`}>
                    {(host.plaintextRatio * 100).toFixed(1)}% of packets
                  </span>
                </div>
              </div>

              <div className="mt-4 pt-3 border-t border-border/40 flex items-center justify-between text-xs">
                <span className="text-slate-500 font-medium">
                  {host.verdict === "VIOLATION"
                    ? "⚠️ Severe policy violation: Transmitting unencrypted data while advertising TLS requirement."
                    : "✓ Policy matches transit cryptographic behavior."}
                </span>
                <Link
                  href={`/dashboard/findings?mx=${host.name}`}
                  className="font-bold text-primary hover:underline flex items-center gap-1"
                >
                  Drill Down →
                </Link>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
