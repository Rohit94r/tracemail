"use client";

import React, { useState, useRef, useEffect } from "react";
import Link from "next/link";
import {
  Wifi,
  WifiOff,
  ChevronDown,
  UploadCloud,
  ExternalLink,
  RefreshCw,
} from "lucide-react";
import { useDashboard } from "./DashboardContext";

export function DashboardHeader() {
  const {
    activeSession,
    sessions,
    switchSession,
    isAirGapped,
    toggleAirGapped,
    runPipeline,
    pipelineRunning,
    backendConnected,
  } = useDashboard();

  const [sessionDropdownOpen, setSessionDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        dropdownRef.current &&
        !dropdownRef.current.contains(event.target as Node)
      ) {
        setSessionDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <header className="sticky top-0 z-30 flex h-18 w-full items-center justify-between border-b border-border/70 bg-white/90 px-6 backdrop-blur-md">
      {/* Left side: Active session selector & status */}
      <div className="flex items-center gap-4">
        {/* Active Session Dropdown */}
        <div className="relative" ref={dropdownRef}>
          <button
            type="button"
            onClick={() => setSessionDropdownOpen(!sessionDropdownOpen)}
            className="flex items-center gap-2.5 rounded-xl border border-border bg-surface-soft px-3.5 py-2 text-sm font-semibold text-heading transition-all hover:border-slate-300 hover:bg-white shadow-xs"
          >
            <span className="h-2 w-2 rounded-full bg-primary animate-pulse" />
            <span className="font-mono text-xs text-slate-500 uppercase">
              Capture:
            </span>
            <span className="max-w-[200px] truncate text-xs font-bold text-slate-900 md:max-w-[280px]">
              {activeSession.filename}
            </span>
            <ChevronDown className="h-3.5 w-3.5 text-slate-400" />
          </button>

          {sessionDropdownOpen && (
            <div className="absolute left-0 top-full mt-2 w-80 md:w-96 rounded-2xl border border-border bg-white p-2 shadow-2xl z-50">
              <div className="px-3 py-2 text-[11px] font-bold uppercase tracking-wider text-slate-400">
                Select Forensic Capture Scenario
              </div>
              <div className="space-y-1">
                {sessions.map((s) => (
                  <button
                    key={s.id}
                    onClick={() => {
                      switchSession(s.id);
                      setSessionDropdownOpen(false);
                    }}
                    className={`w-full text-left rounded-xl p-2.5 transition-colors flex items-start justify-between ${
                      s.id === activeSession.id
                        ? "bg-primary-soft/60 border border-primary/30"
                        : "hover:bg-slate-50"
                    }`}
                  >
                    <div>
                      <div className="text-xs font-bold text-heading">
                        {s.name}
                      </div>
                      <div className="font-mono text-[11px] text-muted">
                        {s.filename} · {s.flows.toLocaleString()} flows
                      </div>
                    </div>
                    <div className="text-right">
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded-md ${
                          s.score >= 80
                            ? "bg-emerald-50 text-emerald-700"
                            : s.score >= 60
                            ? "bg-amber-50 text-amber-700"
                            : "bg-red-50 text-red-700"
                        }`}
                      >
                        {s.grade} ({s.score})
                      </span>
                    </div>
                  </button>
                ))}
              </div>
              <div className="mt-2 pt-2 border-t border-border/50 px-2">
                <Link
                  href="/dashboard"
                  onClick={() => setSessionDropdownOpen(false)}
                  className="flex items-center justify-center gap-1.5 w-full py-1.5 text-xs font-semibold text-primary hover:underline"
                >
                  <UploadCloud className="h-3.5 w-3.5" />
                  Ingest Custom .pcap or Folder
                </Link>
              </div>
            </div>
          )}
        </div>

        {/* Live Engine & DB Badge */}
        <div className="hidden lg:flex items-center gap-2 rounded-lg border border-border/60 bg-slate-50/80 px-2.5 py-1 text-[11px] font-mono">
          <span className={`h-2 w-2 rounded-full ${backendConnected ? "bg-emerald-500 animate-pulse" : "bg-amber-500"}`} />
          <span className={backendConnected ? "text-emerald-700 font-bold" : "text-slate-500 font-medium"}>
            FastAPI: {backendConnected ? "ONLINE (8001)" : "OFFLINE"}
          </span>
          <span className="text-slate-300">|</span>
          <span className={backendConnected ? "text-emerald-700 font-bold" : "text-slate-500 font-medium"}>
            MongoDB: {backendConnected ? "Atlas (platform)" : "cache-mode"}
          </span>
        </div>
      </div>

      {/* Right side: Air-Gap toggle badge & Quick Actions */}
      <div className="flex items-center gap-3">
        {/* Offline Badge (The single most load-bearing UI element from specs) */}
        <button
          type="button"
          onClick={toggleAirGapped}
          className={`flex items-center gap-2 rounded-full px-3 py-1 text-xs font-bold tracking-wide transition-all shadow-xs ${
            isAirGapped
              ? "bg-amber-500/10 text-amber-700 border border-amber-500/30 hover:bg-amber-500/20"
              : "bg-emerald-500/10 text-emerald-700 border border-emerald-500/30 hover:bg-emerald-500/20"
          }`}
          title="Click to toggle between 100% Air-Gapped and DNS-Enriched mode"
        >
          {isAirGapped ? (
            <>
              <WifiOff className="h-3.5 w-3.5 text-amber-600" />
              <span>OFFLINE · METADATA ONLY</span>
            </>
          ) : (
            <>
              <Wifi className="h-3.5 w-3.5 text-emerald-600" />
              <span>ONLINE · DNS ENRICHED</span>
            </>
          )}
        </button>

        {/* Re-analyze Pipeline CTA */}
        <button
          type="button"
          onClick={() => runPipeline()}
          disabled={pipelineRunning}
          className="hidden md:inline-flex items-center gap-1.5 rounded-xl border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 hover:border-slate-300 transition-colors disabled:opacity-50"
        >
          <RefreshCw
            className={`h-3.5 w-3.5 ${pipelineRunning ? "animate-spin text-primary" : "text-slate-400"}`}
          />
          {pipelineRunning ? "Analyzing..." : "Re-evaluate"}
        </button>

        {/* Back to Website */}
        <Link
          href="/"
          className="flex items-center gap-1.5 rounded-xl bg-slate-900 px-3.5 py-1.5 text-xs font-semibold text-white hover:bg-slate-800 transition-colors shadow-xs"
        >
          <span>Landing Page</span>
          <ExternalLink className="h-3 w-3 text-slate-400" />
        </Link>
      </div>
    </header>
  );
}
