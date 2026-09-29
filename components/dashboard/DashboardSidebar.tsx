"use client";

import React, { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import Image from "next/image";
import {
  LayoutDashboard,
  ShieldCheck,
  Network,
  Search,
  FileText,
  PlaySquare,
  Sparkles,
  Crosshair,
  Fingerprint,
  ChevronLeft,
  ChevronRight,
  Plus,
  Minus,
  HelpCircle,
  Shield,
  Layers,
  Lock,
} from "lucide-react";
import { useDashboard } from "./DashboardContext";

export function DashboardSidebar() {
  const pathname = usePathname();
  const { isAirGapped } = useDashboard();
  const [collapsed, setCollapsed] = useState(false);
  const [modulesExpanded, setModulesExpanded] = useState(true);

  // Grouped navigation items per docs/12-ui-spec.md
  const coreNavItems = [
    {
      label: "Ingest & Pipeline",
      href: "/dashboard",
      icon: LayoutDashboard,
      badge: "CORE",
    },
    {
      label: "Posture Score",
      href: "/dashboard/posture",
      icon: ShieldCheck,
      badge: "CORE",
    },
    {
      label: "Delivery Graph",
      href: "/dashboard/graph",
      icon: Network,
      badge: "CORE",
    },
    {
      label: "Findings Explorer",
      href: "/dashboard/findings",
      icon: Search,
      badge: "CORE",
    },
    {
      label: "Reports & Playbooks",
      href: "/dashboard/reports",
      icon: FileText,
      badge: "CORE",
    },
  ];

  const stretchNavItems = [
    {
      label: "Incident Replay",
      href: "/dashboard/replay",
      icon: PlaySquare,
      badge: "LIVE",
    },
    {
      label: "Ask RAG AI",
      href: "/dashboard/ask",
      icon: Sparkles,
      badge: "RAG",
    },
    {
      label: "Attack Lens",
      href: "/dashboard/lens",
      icon: Crosshair,
      badge: "FORECAST",
    },
    {
      label: "Integrity Manifest",
      href: "/dashboard/integrity",
      icon: Fingerprint,
      badge: "SEALED",
    },
  ];

  const isActive = (href: string) => {
    if (href === "/dashboard") {
      return pathname === "/dashboard";
    }
    return pathname.startsWith(href);
  };

  return (
    <aside
      className={`relative flex flex-col border-r border-border bg-white transition-all duration-300 ease-in-out shrink-0 select-none ${
        collapsed ? "w-20" : "w-72"
      }`}
    >
      {/* Top Header: Logo + Collapse/Expand button */}
      <div className="flex h-18 items-center justify-between px-5 border-b border-border/60">
        {!collapsed ? (
          <Link href="/" className="flex items-center gap-2 group">
            <Image
              src="/raven_logo.svg"
              alt="Raven SecureMailScope"
              width={140}
              height={36}
              className="h-8 w-auto transition-transform group-hover:scale-[1.02]"
              priority
            />
          </Link>
        ) : (
          <Link href="/" className="mx-auto">
            <div className="h-9 w-9 rounded-xl bg-primary-soft flex items-center justify-center text-primary font-black text-lg">
              R
            </div>
          </Link>
        )}

        <button
          type="button"
          onClick={() => setCollapsed(!collapsed)}
          className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-400 hover:bg-slate-100 hover:text-slate-700 transition-colors"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? (
            <ChevronRight className="h-4 w-4" />
          ) : (
            <ChevronLeft className="h-4 w-4" />
          )}
        </button>
      </div>

      {/* Navigation Links Scroll Container */}
      <div className="flex-1 overflow-y-auto px-3.5 py-4 space-y-6">
        {/* Core Workspace Section */}
        <div>
          {!collapsed && (
            <div className="px-3 pb-2 text-[11px] font-bold uppercase tracking-[0.14em] text-slate-400">
              Core Modules (FR-1..37)
            </div>
          )}

          <nav className="space-y-1">
            {coreNavItems.map((item) => {
              const active = isActive(item.href);
              const Icon = item.icon;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`group flex items-center gap-3.5 rounded-xl px-3.5 py-2.5 text-sm font-medium transition-all ${
                    active
                      ? "bg-primary-soft/60 text-primary font-semibold shadow-xs"
                      : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
                  }`}
                  title={collapsed ? item.label : undefined}
                >
                  <Icon
                    className={`h-5 w-5 shrink-0 transition-colors ${
                      active
                        ? "text-primary"
                        : "text-slate-400 group-hover:text-slate-700"
                    }`}
                  />
                  {!collapsed && (
                    <span className="truncate flex-1">{item.label}</span>
                  )}
                  {!collapsed && active && (
                    <span className="h-1.5 w-1.5 rounded-full bg-primary" />
                  )}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Forensic & Advanced Section */}
        <div>
          {!collapsed && (
            <div className="px-3 pb-2 text-[11px] font-bold uppercase tracking-[0.14em] text-slate-400">
              Advanced Forensics (FR-38..41)
            </div>
          )}

          <nav className="space-y-1">
            {stretchNavItems.map((item) => {
              const active = isActive(item.href);
              const Icon = item.icon;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`group flex items-center gap-3.5 rounded-xl px-3.5 py-2.5 text-sm font-medium transition-all ${
                    active
                      ? "bg-primary-soft/60 text-primary font-semibold shadow-xs"
                      : "text-slate-600 hover:bg-slate-50 hover:text-slate-900"
                  }`}
                  title={collapsed ? item.label : undefined}
                >
                  <Icon
                    className={`h-5 w-5 shrink-0 transition-colors ${
                      active
                        ? "text-primary"
                        : "text-slate-400 group-hover:text-slate-700"
                    }`}
                  />
                  {!collapsed && (
                    <>
                      <span className="truncate flex-1">{item.label}</span>
                      <span
                        className={`text-[10px] font-bold px-1.5 py-0.5 rounded-md ${
                          active
                            ? "bg-primary text-white"
                            : "bg-slate-100 text-slate-500"
                        }`}
                      >
                        {item.badge}
                      </span>
                    </>
                  )}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Expandable Module Tree (Like in sidebarinspo.png) */}
        {!collapsed && (
          <div className="border-t border-border/60 pt-4">
            <button
              type="button"
              onClick={() => setModulesExpanded(!modulesExpanded)}
              className="flex w-full items-center justify-between px-3 py-2 text-xs font-semibold text-slate-500 hover:text-slate-800 transition-colors"
            >
              <span className="flex items-center gap-2">
                <Layers className="h-3.5 w-3.5 text-slate-400" />
                MTA Inspection Rules
              </span>
              {modulesExpanded ? (
                <Minus className="h-3.5 w-3.5" />
              ) : (
                <Plus className="h-3.5 w-3.5" />
              )}
            </button>

            {modulesExpanded && (
              <div className="mt-1 space-y-0.5 pl-6 pr-2 text-xs text-slate-500">
                <Link
                  href="/dashboard/findings?module=SMS-PROTO"
                  className="block rounded-lg px-2.5 py-1.5 hover:bg-slate-100 hover:text-slate-900 transition-colors"
                >
                  SMS-PROTO (STARTTLS State)
                </Link>
                <Link
                  href="/dashboard/findings?module=SMS-CIPH"
                  className="block rounded-lg px-2.5 py-1.5 hover:bg-slate-100 hover:text-slate-900 transition-colors"
                >
                  SMS-CIPH (Cipher & Sweet32)
                </Link>
                <Link
                  href="/dashboard/findings?module=SMS-X509"
                  className="block rounded-lg px-2.5 py-1.5 hover:bg-slate-100 hover:text-slate-900 transition-colors"
                >
                  SMS-X509 (Cert Validation)
                </Link>
                <Link
                  href="/dashboard/findings?module=SMS-ENF"
                  className="block rounded-lg px-2.5 py-1.5 hover:bg-slate-100 hover:text-slate-900 transition-colors"
                >
                  SMS-ENF (MTA-STS & DANE)
                </Link>
                <Link
                  href="/dashboard/findings?module=SMS-RADAR"
                  className="block rounded-lg px-2.5 py-1.5 hover:bg-slate-100 hover:text-slate-900 transition-colors"
                >
                  SMS-RADAR (Downgrade Radar)
                </Link>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Bottom Section: Air-Gapped Sovereign Card (matching sidebarinspo.png) */}
      <div className="p-3.5 border-t border-border/60">
        {!collapsed ? (
          <div className="rounded-2xl border border-border/80 bg-surface-soft p-4 text-center">
            <div className="flex items-center justify-center gap-1.5 mb-1 text-xs font-bold uppercase tracking-wider text-heading">
              <Shield className="h-3.5 w-3.5 text-primary" />
              Air-Gapped Node
            </div>
            <p className="text-xs text-muted leading-relaxed mb-3">
              {isAirGapped
                ? "100% offline mode active. Passive ingestion with zero external egress."
                : "DNS-enriched mode. Querying DNSSEC & MTA-STS policy daemons."}
            </p>
            <Link
              href="/dashboard/integrity"
              className="inline-flex w-full items-center justify-center rounded-xl border border-primary px-3 py-2 text-xs font-bold text-primary transition-all hover:bg-primary hover:text-white"
            >
              Verify SHA-256 Manifest
            </Link>
          </div>
        ) : (
          <Link
            href="/dashboard/integrity"
            className="flex h-10 w-10 mx-auto items-center justify-center rounded-xl border border-primary/40 text-primary hover:bg-primary-soft transition-colors"
            title="Air-Gapped Sovereign Node - Verify Manifest"
          >
            <Lock className="h-4 w-4" />
          </Link>
        )}

        {/* Footer Link: Usages Guide / RFC Reference */}
        <div className="mt-3 pt-3 border-t border-border/40">
          <Link
            href="/#faq"
            className={`flex items-center gap-2 text-xs font-medium text-slate-500 hover:text-slate-900 transition-colors ${
              collapsed ? "justify-center" : "px-2"
            }`}
            title="Usage Guide & RFC Specifications"
          >
            <HelpCircle className="h-4 w-4 text-slate-400" />
            {!collapsed && <span>Usages Guide & RFCs</span>}
          </Link>
        </div>
      </div>
    </aside>
  );
}
