"use client";

import React, { useState } from "react";

export function RavenDashboardPreview() {
  const [activeTab, setActiveTab] = useState<"posture" | "graph" | "findings">("posture");

  return (
    <div className="w-full rounded-xl md:rounded-2xl bg-[#0B0F17] text-white border border-slate-800 shadow-2xl overflow-hidden font-sans">
      {/* Top Header / App Shell */}
      <div className="flex flex-wrap items-center justify-between border-b border-slate-800/80 bg-[#0F1420] px-4 py-3 md:px-6">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-primary/20 text-primary font-bold text-sm border border-primary/30">
              R
            </span>
            <span className="font-bold text-base tracking-tight text-white">RAVEN</span>
          </div>
          <span className="hidden sm:inline-block text-xs text-slate-500">|</span>
          <span className="hidden sm:inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-400">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
            AIR-GAPPED · OFFLINE ONLY
          </span>
        </div>

        <div className="flex items-center gap-2 sm:gap-4 text-xs">
          <div className="hidden lg:flex items-center gap-2 rounded-lg bg-slate-900 border border-slate-800 px-3 py-1.5 text-slate-300 font-mono">
            <span className="text-slate-500">CAPTURE:</span>
            <span className="text-amber-400 font-medium">smtp-boundary-09.pcapng</span>
          </div>
          <div className="flex items-center gap-2 rounded-lg bg-slate-900 border border-slate-800 px-3 py-1.5 text-slate-300 font-mono text-[11px]">
            <span className="text-slate-500">SHA256:</span>
            <span className="text-primary">7f39b2...4a</span>
          </div>
        </div>
      </div>

      {/* Secondary Bar / Navigation Tabs */}
      <div className="flex items-center justify-between border-b border-slate-800/60 bg-[#0B0F17] px-4 md:px-6 py-2">
        <div className="flex items-center gap-1 sm:gap-2">
          <button
            onClick={() => setActiveTab("posture")}
            className={`rounded-lg px-3 py-1 text-xs font-semibold transition-colors ${
              activeTab === "posture"
                ? "bg-primary text-white"
                : "text-slate-400 hover:text-white"
            }`}
          >
            1. Posture Overview
          </button>
          <button
            onClick={() => setActiveTab("graph")}
            className={`rounded-lg px-3 py-1 text-xs font-semibold transition-colors ${
              activeTab === "graph"
                ? "bg-primary text-white"
                : "text-slate-400 hover:text-white"
            }`}
          >
            2. Delivery Graph
          </button>
          <button
            onClick={() => setActiveTab("findings")}
            className={`rounded-lg px-3 py-1 text-xs font-semibold transition-colors ${
              activeTab === "findings"
                ? "bg-primary text-white"
                : "text-slate-400 hover:text-white"
            }`}
          >
            3. Forensic Findings (3)
          </button>
        </div>

        <div className="hidden sm:flex items-center gap-2 text-xs text-slate-400">
          <span>Flows: <strong className="text-white">1,429</strong></span>
          <span>·</span>
          <span>Packets: <strong className="text-white">48,210</strong></span>
        </div>
      </div>

      {/* Main Dashboard Canvas */}
      <div className="p-4 md:p-6 space-y-6">
        {/* Top 4 KPI Metrics */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 md:gap-4">
          {/* KPI 1 */}
          <div className="rounded-xl border border-slate-800 bg-[#121826] p-4 relative overflow-hidden">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400">POSTURE SCORE</span>
              <span className="rounded bg-emerald-500/20 text-emerald-400 text-[10px] font-bold px-1.5 py-0.5">
                GRADE B+
              </span>
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-black text-white">78</span>
              <span className="text-xs text-slate-400 font-mono">[CI: 71 – 84]</span>
            </div>
            <p className="mt-1 text-[11px] text-amber-400">
              ⚠ 1 hop chain unobservable (TLS 1.3)
            </p>
          </div>

          {/* KPI 2 */}
          <div className="rounded-xl border border-slate-800 bg-[#121826] p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400">DOWNGRADE RADAR</span>
              <span className="rounded bg-red-500/20 text-red-400 text-[10px] font-bold px-1.5 py-0.5">
                ALERT
              </span>
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-black text-red-400">1</span>
              <span className="text-xs text-slate-400">Stripping Flow</span>
            </div>
            <p className="mt-1 text-[11px] text-slate-400">
              STARTTLS stripped by peer relay
            </p>
          </div>

          {/* KPI 3 */}
          <div className="rounded-xl border border-slate-800 bg-[#121826] p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400">ENFORCEMENT CHECK</span>
              <span className="rounded bg-amber-500/20 text-amber-400 text-[10px] font-bold px-1.5 py-0.5">
                DRIFT
              </span>
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-black text-amber-400">2</span>
              <span className="text-xs text-slate-400">MTA-STS Mismatches</span>
            </div>
            <p className="mt-1 text-[11px] text-slate-400">
              Claimed: enforce · Observed: plaintext
            </p>
          </div>

          {/* KPI 4 */}
          <div className="rounded-xl border border-slate-800 bg-[#121826] p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-400">CIPHER HEALTH</span>
              <span className="rounded bg-primary/20 text-primary text-[10px] font-bold px-1.5 py-0.5">
                PQC READY
              </span>
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-3xl font-black text-white">91%</span>
              <span className="text-xs text-slate-400">PFS Negotiated</span>
            </div>
            <p className="mt-1 text-[11px] text-slate-400">
              4 MTAs support Hybrid Kyber-768
            </p>
          </div>
        </div>

        {/* Middle Section: Delivery Graph & Protocol Breakdown */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          {/* Delivery Graph Visualization */}
          <div className="lg:col-span-8 rounded-xl border border-slate-800 bg-[#121826] p-4 md:p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-primary" />
                <h4 className="text-xs md:text-sm font-semibold text-white tracking-wide">
                  TRANSIT HOP TOPOLOGY & WEAKEST LINK PINPOINT
                </h4>
              </div>
              <span className="text-[11px] text-slate-400 font-mono">
                PASSIVE RECONSTRUCTION
              </span>
            </div>

            {/* Visual Hop Flow */}
            <div className="relative rounded-lg border border-slate-800/80 bg-[#0A0E17] p-4 md:p-6 overflow-x-auto">
              <div className="min-w-[540px] flex items-center justify-between">
                {/* Node 1: Sender / Egress */}
                <div className="flex flex-col items-center">
                  <div className="h-12 w-12 rounded-xl bg-slate-900 border-2 border-emerald-500/80 flex items-center justify-center text-emerald-400 font-bold text-xs shadow-lg shadow-emerald-500/10">
                    MX-01
                  </div>
                  <span className="mt-2 text-xs font-semibold text-white">egress.gov.in</span>
                  <span className="text-[10px] text-emerald-400 font-mono">TLS 1.3 · Grade A</span>
                </div>

                {/* Arrow 1 */}
                <div className="flex-1 px-3 flex flex-col items-center">
                  <span className="text-[10px] text-emerald-400 font-mono mb-1">
                    AES-256-GCM (OK)
                  </span>
                  <div className="w-full h-0.5 bg-emerald-500/60 relative">
                    <div className="absolute right-0 -top-1 border-t-4 border-t-transparent border-b-4 border-b-transparent border-l-4 border-l-emerald-400" />
                  </div>
                  <span className="text-[9px] text-slate-500 mt-1">942 msgs (66%)</span>
                </div>

                {/* Node 2: Intermediate Relay */}
                <div className="flex flex-col items-center">
                  <div className="h-12 w-12 rounded-xl bg-slate-900 border-2 border-amber-500/80 flex items-center justify-center text-amber-400 font-bold text-xs shadow-lg shadow-amber-500/10">
                    RELAY
                  </div>
                  <span className="mt-2 text-xs font-semibold text-white">relay-hub.net</span>
                  <span className="text-[10px] text-amber-400 font-mono">TLS 1.2 · Grade B</span>
                </div>

                {/* Arrow 2: Weakest Link Alert */}
                <div className="flex-1 px-3 flex flex-col items-center">
                  <span className="text-[10px] text-red-400 font-mono font-bold animate-pulse mb-1">
                    ⚡ STRIPPED TO PLAINTEXT
                  </span>
                  <div className="w-full h-0.5 bg-red-500/80 border-t border-dashed border-red-400 relative">
                    <div className="absolute right-0 -top-1 border-t-4 border-t-transparent border-b-4 border-b-transparent border-l-4 border-l-red-400" />
                  </div>
                  <span className="text-[9px] text-red-400 font-semibold mt-1">WEAKEST HOP (34%)</span>
                </div>

                {/* Node 3: Target Peer */}
                <div className="flex flex-col items-center">
                  <div className="h-12 w-12 rounded-xl bg-slate-900 border-2 border-red-500 flex items-center justify-center text-red-400 font-bold text-xs shadow-lg shadow-red-500/20 animate-pulse">
                    PEER
                  </div>
                  <span className="mt-2 text-xs font-semibold text-white">mail.legacy-corp.org</span>
                  <span className="text-[10px] text-red-400 font-mono font-bold">VULNERABLE (Grade E)</span>
                </div>
              </div>
            </div>
          </div>

          {/* Right Protocol Breakdown */}
          <div className="lg:col-span-4 rounded-xl border border-slate-800 bg-[#121826] p-4 md:p-5 flex flex-col justify-between">
            <div>
              <h4 className="text-xs md:text-sm font-semibold text-white tracking-wide mb-4">
                OBSERVED ENCRYPTION RATIO
              </h4>

              <div className="space-y-3">
                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-slate-300">TLS 1.3 (RFC 8446)</span>
                    <span className="text-emerald-400 font-mono font-semibold">72.4%</span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div className="bg-emerald-500 h-full rounded-full" style={{ width: "72.4%" }} />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-slate-300">TLS 1.2 (PFS Ciphers)</span>
                    <span className="text-amber-400 font-mono font-semibold">17.8%</span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div className="bg-amber-500 h-full rounded-full" style={{ width: "17.8%" }} />
                  </div>
                </div>

                <div>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-slate-300">Plaintext / Stripped</span>
                    <span className="text-red-400 font-mono font-bold">9.8%</span>
                  </div>
                  <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
                    <div className="bg-red-500 h-full rounded-full" style={{ width: "9.8%" }} />
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-slate-800/80">
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-400">DNS Policy Match:</span>
                <span className="text-red-400 font-semibold font-mono">FAIL (MTA-STS Drift)</span>
              </div>
            </div>
          </div>
        </div>

        {/* Bottom Findings Table */}
        <div className="rounded-xl border border-slate-800 bg-[#121826] p-4 md:p-5">
          <div className="flex items-center justify-between mb-3">
            <h4 className="text-xs md:text-sm font-semibold text-white tracking-wide">
              FORENSIC EVIDENCE & FINDINGS CHAIN
            </h4>
            <span className="text-xs text-slate-400">Audit-ready drilldown with exact packet offsets</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 text-[11px]">
                  <th className="pb-2 font-semibold">SEVERITY</th>
                  <th className="pb-2 font-semibold">RULE ID</th>
                  <th className="pb-2 font-semibold">AFFECTED HOST</th>
                  <th className="pb-2 font-semibold">EVIDENCE OFFSET</th>
                  <th className="pb-2 font-semibold">VERDICT</th>
                  <th className="pb-2 font-semibold text-right">HASH SIGN</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                <tr>
                  <td className="py-2.5">
                    <span className="rounded bg-red-500/20 text-red-400 px-2 py-0.5 font-bold text-[10px]">
                      CRITICAL
                    </span>
                  </td>
                  <td className="py-2.5 text-white font-semibold">SMS-STRIP-001</td>
                  <td className="py-2.5 text-slate-300">mail.legacy-corp.org:25</td>
                  <td className="py-2.5 text-amber-400">Pkt #1,429 [0x04f2]</td>
                  <td className="py-2.5 text-red-300">STARTTLS announcement suppressed</td>
                  <td className="py-2.5 text-right text-slate-500 font-mono">sha256:4a8b1...</td>
                </tr>
                <tr>
                  <td className="py-2.5">
                    <span className="rounded bg-amber-500/20 text-amber-400 px-2 py-0.5 font-bold text-[10px]">
                      HIGH
                    </span>
                  </td>
                  <td className="py-2.5 text-white font-semibold">SMS-X509-004</td>
                  <td className="py-2.5 text-slate-300">relay-hub.net:587</td>
                  <td className="py-2.5 text-amber-400">Pkt #842 [0x01a8]</td>
                  <td className="py-2.5 text-amber-300">Cert CN mismatch (claims old.internal)</td>
                  <td className="py-2.5 text-right text-slate-500 font-mono">sha256:7c91e...</td>
                </tr>
                <tr>
                  <td className="py-2.5">
                    <span className="rounded bg-blue-500/20 text-blue-400 px-2 py-0.5 font-bold text-[10px]">
                      MEDIUM
                    </span>
                  </td>
                  <td className="py-2.5 text-white font-semibold">SMS-ENF-002</td>
                  <td className="py-2.5 text-slate-300">mx-backup.gov.in:25</td>
                  <td className="py-2.5 text-amber-400">Pkt #1,104 [0x08b4]</td>
                  <td className="py-2.5 text-blue-300">MTA-STS policy enforce violated</td>
                  <td className="py-2.5 text-right text-slate-500 font-mono">sha256:3d28f...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
