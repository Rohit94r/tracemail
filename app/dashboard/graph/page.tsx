"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  Network,
  AlertTriangle,
  ShieldAlert,
  Layers,
} from "lucide-react";
import { useDashboard } from "@/components/dashboard/DashboardContext";

export default function DeliveryGraphPage() {
  const { graphEdges, activeSession } = useDashboard();
  const [selectedNode, setSelectedNode] = useState<string>("peer-weak-relay");

  const nodeDetails: Record<
    string,
    { title: string; subtitle: string; desc: string; stat: string; link?: string; alert?: boolean }
  > = {
    "peer-weak-relay": {
      title: "Weakest Hop Alert: relay-gw.partner.net",
      subtitle: "Hop 2 MITM Interception",
      desc: "Attacker on Hop 2 stripped STARTTLS from downstream EHLO response. 890 sensitive corporate messages leaked in unencrypted cleartext across this edge.",
      stat: "17.4% Outbound Leakage",
      link: "/dashboard/findings?mx=relay-gw.partner.net",
      alert: true,
    },
    "peer-google": {
      title: "Verified Peer: aspmx.l.google.com",
      subtitle: "Google Workspace Ingress",
      desc: "Mandatory TLS 1.3 negotiated with X25519 forward secrecy and valid SAN certificate chain. Zero downgrade anomalies observed.",
      stat: "48.0% Verified Transit",
      alert: false,
    },
    "peer-msft": {
      title: "Verified Peer: mail.protection.outlook.com",
      subtitle: "Microsoft 365 Cloud Relay",
      desc: "Modern TLS 1.3 with AES-256-GCM cipher suite and active MTA-STS DNS validation. Consistent cryptographic posture.",
      stat: "24.0% Verified Transit",
      alert: false,
    },
    "corp-mx1": {
      title: "Internal Anchor: mx1.corp.net",
      subtitle: "Primary Organization Gateway",
      desc: "Central ingress MTA receiving traffic on Port 25. High internal posture score (88/100), but vulnerable downstream peer hops degrade total safety.",
      stat: "100% Ingress Hub",
      alert: false,
    },
  };

  const activeNodeInfo = nodeDetails[selectedNode] || nodeDetails["peer-weak-relay"];

  return (
    <div className="space-y-8">
      {/* Title & Concept Header */}
      <div>
        <div className="inline-flex items-center gap-1.5 rounded-md bg-slate-100 px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider text-slate-700 mb-2">
          <Network className="h-3.5 w-3.5 text-slate-600" />
          Hop-by-Hop Transit Graph
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight text-heading">
          Delivery Topology & Weakest-Hop Exposure
        </h1>
        <p className="mt-1 text-sm text-body">
          &quot;Your internal mail servers may be A-grade, but confidential messages leak across external peer transit hops.&quot;
        </p>
      </div>

      {/* Main Delivery Graph Canvas */}
      <div className="rounded-3xl border border-border bg-white p-6 shadow-xs space-y-4">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 border-b border-border/60 pb-4">
          <div>
            <h3 className="text-base font-bold text-heading">
              Enterprise Transit Graph (Session: {activeSession.id} · {graphEdges.length} Active Edges)
            </h3>
            <p className="text-xs text-muted">
              Interactive topology map. Edge thickness represents traffic density; edge color reflects peer transit hygiene.
            </p>
          </div>

          <div className="flex items-center gap-3 text-xs">
            <span className="flex items-center gap-1.5 text-emerald-700 font-semibold">
              <span className="h-3 w-3 rounded-full bg-emerald-500" /> TLS 1.3 Verified
            </span>
            <span className="flex items-center gap-1.5 text-blue-700 font-semibold">
              <span className="h-3 w-3 rounded-full bg-blue-500" /> TLS 1.2 Encrypted
            </span>
            <span className="flex items-center gap-1.5 text-red-700 font-semibold">
              <span className="h-3 w-3 rounded-full bg-red-500 animate-ping" />
              Weakest Hop (Stripped Cleartext)
            </span>
          </div>
        </div>

        {/* SVG Interactive Topology Visualization */}
        <div className="relative h-[480px] w-full rounded-2xl bg-slate-950 overflow-hidden border border-slate-800">
          {/* Subtle grid pattern */}
          <div className="absolute inset-0 bg-[radial-gradient(#1e293b_1px,transparent_1px)] [background-size:24px_24px] opacity-40" />

          <svg className="h-full w-full select-none" viewBox="0 0 900 480">
            {/* Center Origin Node: mx1.corp.net at (260, 240) */}
            {/* Outbound peer edges */}

            {/* Edge 1: mx1.corp.net -> Google (680, 100) */}
            <line
              x1="260"
              y1="240"
              x2="680"
              y2="100"
              stroke="#10b981"
              strokeWidth="6"
              strokeOpacity="0.8"
            />
            <text x="470" y="155" fill="#a7f3d0" fontSize="10" fontFamily="monospace" textAnchor="middle">
              2,450 msgs (48%) TLS 1.3
            </text>

            {/* Edge 2: mx1.corp.net -> Outlook (720, 240) */}
            <line
              x1="260"
              y1="240"
              x2="720"
              y2="240"
              stroke="#10b981"
              strokeWidth="4"
              strokeOpacity="0.8"
            />
            <text x="490" y="230" fill="#a7f3d0" fontSize="10" fontFamily="monospace" textAnchor="middle">
              1,220 msgs (24%) TLS 1.3
            </text>

            {/* Edge 3: WEAKEST HOP -> relay-gw.partner.net (680, 380) */}
            <line
              x1="260"
              y1="240"
              x2="680"
              y2="380"
              stroke="#ef4444"
              strokeWidth="4.5"
              strokeDasharray="6,4"
              className="animate-pulse"
            />
            {/* Warning triangle in middle of weakest hop */}
            <circle cx="470" cy="310" r="14" fill="#450a0a" stroke="#ef4444" strokeWidth="2" />
            <text x="470" y="315" fill="#ef4444" fontSize="12" fontWeight="bold" textAnchor="middle">
              ⚠️
            </text>
            <text x="470" y="335" fill="#f87171" fontSize="11" fontFamily="monospace" fontWeight="bold" textAnchor="middle">
              890 msgs (17%) STRIPPED CLEARTEXT!
            </text>

            {/* NODES */}
            {/* Center Enterprise Node */}
            <g transform="translate(260, 240)" className="cursor-pointer" onClick={() => setSelectedNode("corp-mx1")}>
              <circle r="44" fill="#0f172a" stroke={selectedNode === "corp-mx1" ? "#60a5fa" : "#38bdf8"} strokeWidth="3" />
              <circle r="36" fill="#1e293b" />
              <text y="-6" fill="#f8fafc" fontSize="12" fontWeight="bold" textAnchor="middle">
                mx1.corp.net
              </text>
              <text y="12" fill="#38bdf8" fontSize="10" fontFamily="monospace" textAnchor="middle">
                PRIMARY INGRESS
              </text>
              <text y="26" fill="#a7f3d0" fontSize="10" fontWeight="bold" textAnchor="middle">
                Grade A- (88/100)
              </text>
            </g>

            {/* Peer Node 1: Google */}
            <g transform="translate(680, 100)" className="cursor-pointer" onClick={() => setSelectedNode("peer-google")}>
              <circle r="36" fill="#064e3b" stroke={selectedNode === "peer-google" ? "#60a5fa" : "#10b981"} strokeWidth="2" />
              <text y="-4" fill="#ffffff" fontSize="11" fontWeight="bold" textAnchor="middle">
                aspmx.google
              </text>
              <text y="12" fill="#34d399" fontSize="10" fontWeight="bold" textAnchor="middle">
                Grade A+ (98)
              </text>
            </g>

            {/* Peer Node 2: Microsoft */}
            <g transform="translate(720, 240)" className="cursor-pointer" onClick={() => setSelectedNode("peer-msft")}>
              <circle r="36" fill="#064e3b" stroke={selectedNode === "peer-msft" ? "#60a5fa" : "#10b981"} strokeWidth="2" />
              <text y="-4" fill="#ffffff" fontSize="11" fontWeight="bold" textAnchor="middle">
                outlook.com
              </text>
              <text y="12" fill="#34d399" fontSize="10" fontWeight="bold" textAnchor="middle">
                Grade A (92)
              </text>
            </g>

            {/* Peer Node 3: WEAKEST HOP (relay-gw.partner.net) */}
            <g
              transform="translate(680, 380)"
              className="cursor-pointer group"
              onClick={() => setSelectedNode("peer-weak-relay")}
            >
              <circle r="46" fill="#450a0a" stroke={selectedNode === "peer-weak-relay" ? "#60a5fa" : "#ef4444"} strokeWidth="3" className="animate-pulse" />
              <circle r="38" fill="#7f1d1d" />
              <text y="-6" fill="#fecaca" fontSize="11" fontWeight="bold" textAnchor="middle">
                relay-gw.partner
              </text>
              <text y="10" fill="#f87171" fontSize="10" fontWeight="bold" textAnchor="middle">
                GRADE E (42/100)
              </text>
              <text y="24" fill="#ef4444" fontSize="9" fontWeight="bold" textAnchor="middle">
                CRITICAL LEAK
              </text>
            </g>
          </svg>

          {/* Quick Node Details HUD overlay */}
          <div className="absolute bottom-4 left-4 rounded-xl border border-slate-800 bg-slate-900/90 p-4 text-xs text-slate-300 backdrop-blur-md max-w-sm">
            <div className="font-bold text-white flex items-center gap-2 mb-1">
              {activeNodeInfo.alert ? (
                <AlertTriangle className="h-4 w-4 text-red-400" />
              ) : (
                <span className="h-2 w-2 rounded-full bg-emerald-400" />
              )}
              {activeNodeInfo.title}
            </div>
            <p className="text-slate-400 leading-relaxed">
              {activeNodeInfo.desc}
            </p>
            <div className="mt-3 flex items-center justify-between">
              <span className="font-mono text-primary font-bold">{activeNodeInfo.stat}</span>
              {activeNodeInfo.link && (
                <Link
                  href={activeNodeInfo.link}
                  className="text-primary font-bold hover:underline flex items-center gap-1"
                >
                  Inspect Findings →
                </Link>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Weakest-Hop Ranked List & Exposure Histogram */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Ranked Weakest Hop List (FR-26) */}
        <div className="rounded-3xl border border-border bg-white p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-bold text-heading flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-red-500" />
              Ranked Weakest-Hop Transit Peers
            </h3>
            <span className="text-xs font-mono text-muted">Prioritized by Risk</span>
          </div>

          <div className="space-y-3">
            <div className="rounded-2xl border border-red-200 bg-red-50/40 p-4">
              <div className="flex items-start justify-between">
                <div>
                  <div className="font-mono font-bold text-slate-900 text-xs">
                    1. relay-gw.partner.net (198.51.100.14)
                  </div>
                  <div className="text-xs text-red-700 font-medium mt-1">
                    STARTTLS Stripped · RFC 3207 Violation · Zero MTA-STS
                  </div>
                </div>
                <span className="rounded-lg bg-red-600 px-2.5 py-0.5 text-xs font-extrabold text-white">
                  Grade E (42)
                </span>
              </div>
              <div className="mt-3 flex items-center justify-between text-xs text-slate-600 border-t border-red-200/60 pt-2">
                <span>Volume: <strong>890 msgs (17.4% outbound)</strong></span>
                <Link
                  href="/dashboard/replay?finding=FIND-001"
                  className="font-bold text-red-700 hover:underline"
                >
                  Forensic Replay →
                </Link>
              </div>
            </div>

            <div className="rounded-2xl border border-amber-200 bg-amber-50/40 p-4">
              <div className="flex items-start justify-between">
                <div>
                  <div className="font-mono font-bold text-slate-900 text-xs">
                    2. legacy-mx.backup.internal (198.51.100.88)
                  </div>
                  <div className="text-xs text-amber-700 font-medium mt-1">
                    Sweet32 3DES Ciphers · CBC Mode · Broken DANE TLSA
                  </div>
                </div>
                <span className="rounded-lg bg-amber-500 px-2.5 py-0.5 text-xs font-extrabold text-white">
                  Grade D- (54)
                </span>
              </div>
              <div className="mt-3 flex items-center justify-between text-xs text-slate-600 border-t border-amber-200/60 pt-2">
                <span>Volume: <strong>180 msgs (3.5% outbound)</strong></span>
                <Link
                  href="/dashboard/findings?mx=legacy-mx.backup.internal"
                  className="font-bold text-amber-700 hover:underline"
                >
                  View Details →
                </Link>
              </div>
            </div>
          </div>
        </div>

        {/* Transit Exposure Histogram (FR-27) */}
        <div className="rounded-3xl border border-border bg-white p-6 shadow-xs space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-bold text-heading flex items-center gap-2">
              <Layers className="h-4 w-4 text-primary" />
              Cryptographic Exposure Distribution
            </h3>
            <span className="text-xs font-mono text-muted">Across 5,120 Messages</span>
          </div>

          <p className="text-xs text-muted leading-relaxed">
            Percentage of organization messages transmitted under each cryptographic assurance bracket:
          </p>

          <div className="space-y-3 pt-2">
            <div>
              <div className="flex justify-between text-xs font-semibold mb-1">
                <span className="text-emerald-700">TLS 1.3 / Strict Pinning (Grade A)</span>
                <span className="font-mono">3,670 msgs (71.7%)</span>
              </div>
              <div className="h-3 w-full rounded-full bg-slate-100 overflow-hidden">
                <div className="h-full bg-emerald-500 rounded-full" style={{ width: "71.7%" }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-semibold mb-1">
                <span className="text-blue-700">TLS 1.2 Forward Secrecy (Grade B)</span>
                <span className="font-mono">380 msgs (7.4%)</span>
              </div>
              <div className="h-3 w-full rounded-full bg-slate-100 overflow-hidden">
                <div className="h-full bg-blue-500 rounded-full" style={{ width: "7.4%" }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-semibold mb-1">
                <span className="text-amber-700">Legacy CBC / Weak Ciphers (Grade C/D)</span>
                <span className="font-mono">180 msgs (3.5%)</span>
              </div>
              <div className="h-3 w-full rounded-full bg-slate-100 overflow-hidden">
                <div className="h-full bg-amber-500 rounded-full" style={{ width: "3.5%" }} />
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs font-semibold mb-1">
                <span className="text-red-700 font-bold">Unencrypted Cleartext / Stripped (Grade E)</span>
                <span className="font-mono text-red-600 font-bold">890 msgs (17.4%)</span>
              </div>
              <div className="h-3 w-full rounded-full bg-slate-100 overflow-hidden">
                <div className="h-full bg-red-500 rounded-full animate-pulse" style={{ width: "17.4%" }} />
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
