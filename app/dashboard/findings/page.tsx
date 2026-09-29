"use client";

import React, { useState } from "react";
import {
  Search,
  ArrowUpDown,
  Download,
  ChevronRight,
} from "lucide-react";
import { useDashboard, Severity } from "@/components/dashboard/DashboardContext";
import { EvidenceDrawer } from "@/components/dashboard/EvidenceDrawer";

export default function FindingsPage() {
  const { findings, selectedFinding, setSelectedFinding, activeSession } = useDashboard();

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [stateFilter, setStateFilter] = useState<string>("ALL");
  const [sortBy, setSortBy] = useState<"cvss" | "severity" | "confidence">("cvss");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");

  // Filtering
  const filteredFindings = findings.filter((f) => {
    const matchesSearch =
      f.ruleTitle.toLowerCase().includes(search.toLowerCase()) ||
      f.ruleId.toLowerCase().includes(search.toLowerCase()) ||
      f.mxHost.toLowerCase().includes(search.toLowerCase()) ||
      f.cwe.toLowerCase().includes(search.toLowerCase());

    const matchesSeverity = severityFilter === "ALL" || f.severity === severityFilter;
    const matchesState = stateFilter === "ALL" || f.state === stateFilter;

    return matchesSearch && matchesSeverity && matchesState;
  });

  // Sorting
  const sortedFindings = [...filteredFindings].sort((a, b) => {
    let diff = 0;
    if (sortBy === "cvss") {
      diff = a.cvss - b.cvss;
    } else if (sortBy === "confidence") {
      diff = a.confidence - b.confidence;
    } else if (sortBy === "severity") {
      const rank: Record<Severity, number> = {
        CRITICAL: 5,
        HIGH: 4,
        MEDIUM: 3,
        LOW: 2,
        INFO: 1,
      };
      diff = rank[a.severity] - rank[b.severity];
    }
    return sortOrder === "desc" ? -diff : diff;
  });

  const exportCSV = () => {
    const headers = "id,ruleId,severity,state,service,mxHost,cvss,cwe,confidence,byteOffset,spanHash\n";
    const rows = sortedFindings
      .map(
        (f) =>
          `"${f.id}","${f.ruleId}","${f.severity}","${f.state}","${f.service}","${f.mxHost}",${f.cvss},"${f.cwe}",${f.confidence},"${f.provenance.byteOffset}","${f.provenance.spanHash}"`
      )
      .join("\n");
    const blob = new Blob([headers + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `raven_findings_${activeSession.id}.csv`;
    a.click();
  };

  return (
    <div className="space-y-6">
      {/* Title & Section Tag */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-1.5 rounded-md bg-slate-100 px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider text-slate-700 mb-2">
            <Search className="h-3.5 w-3.5 text-slate-600" />
            Risk-Ranked Evidence Truth
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-heading">
            Forensic Findings Explorer
          </h1>
          <p className="mt-1 text-sm text-body">
            Every finding links directly to a verifiable byte offset, packet frame number, and RFC clause. Click any row to slide open the forensic evidence chain.
          </p>
        </div>

        <button
          onClick={exportCSV}
          className="inline-flex items-center gap-2 rounded-xl border border-border bg-white px-4 py-2.5 text-xs font-bold text-slate-700 hover:bg-slate-50 transition-colors shadow-xs"
        >
          <Download className="h-4 w-4" />
          Export Findings CSV
        </button>
      </div>

      {/* Filter Bar (FR-28 specification) */}
      <div className="rounded-2xl border border-border bg-white p-4 shadow-xs space-y-3">
        <div className="flex flex-col md:flex-row md:items-center gap-3 justify-between">
          {/* Search Input */}
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by rule (SMS-ENF), host, CVE/CWE, or keyword..."
              className="w-full rounded-xl border border-border bg-surface-soft pl-10 pr-4 py-2 text-xs font-medium text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500/20"
            />
          </div>

          {/* Sort Controls */}
          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-500 font-semibold">Sort by:</span>
            <button
              onClick={() => {
                if (sortBy === "cvss") setSortOrder(sortOrder === "asc" ? "desc" : "asc");
                else {
                  setSortBy("cvss");
                  setSortOrder("desc");
                }
              }}
              className={`rounded-lg px-2.5 py-1.5 font-semibold transition-colors flex items-center gap-1 ${
                sortBy === "cvss" ? "bg-slate-900 text-white" : "bg-slate-100 text-slate-700 hover:bg-slate-200"
              }`}
            >
              CVSS <ArrowUpDown className="h-3 w-3" />
            </button>
            <button
              onClick={() => {
                if (sortBy === "severity") setSortOrder(sortOrder === "asc" ? "desc" : "asc");
                else {
                  setSortBy("severity");
                  setSortOrder("desc");
                }
              }}
              className={`rounded-lg px-2.5 py-1.5 font-semibold transition-colors flex items-center gap-1 ${
                sortBy === "severity" ? "bg-slate-900 text-white" : "bg-slate-100 text-slate-700 hover:bg-slate-200"
              }`}
            >
              Severity <ArrowUpDown className="h-3 w-3" />
            </button>
          </div>
        </div>

        {/* Filter Chips */}
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-border/60">
          <span className="text-xs font-bold text-slate-400 uppercase tracking-wider mr-1">
            Severity:
          </span>
          {["ALL", "CRITICAL", "HIGH", "MEDIUM", "INFO"].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`rounded-lg px-3 py-1 text-xs font-bold transition-all ${
                severityFilter === sev
                  ? "bg-slate-900 text-white shadow-xs"
                  : "bg-surface-soft text-slate-600 hover:bg-slate-200"
              }`}
            >
              {sev}
            </button>
          ))}

          <span className="text-xs font-bold text-slate-400 uppercase tracking-wider ml-4 mr-1">
            Tri-State:
          </span>
          {["ALL", "VULNERABLE", "SECURE", "NOT-OBSERVABLE"].map((st) => (
            <button
              key={st}
              onClick={() => setStateFilter(st)}
              className={`rounded-lg px-3 py-1 text-xs font-bold transition-all ${
                stateFilter === st
                  ? "bg-slate-900 text-white shadow-xs"
                  : "bg-surface-soft text-slate-600 hover:bg-slate-200"
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Findings Table */}
      <div className="rounded-3xl border border-border bg-white shadow-xs overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-border bg-surface-soft text-slate-500 font-bold uppercase text-[10px]">
                <th className="py-3.5 px-4">Severity</th>
                <th className="py-3.5 px-3">Rule ID</th>
                <th className="py-3.5 px-4">Description / Finding</th>
                <th className="py-3.5 px-3">Observed Host</th>
                <th className="py-3.5 px-3 text-center">Service</th>
                <th className="py-3.5 px-3 text-center">CVSS</th>
                <th className="py-3.5 px-3 text-center">Confidence</th>
                <th className="py-3.5 px-3">State</th>
                <th className="py-3.5 px-4 text-right">Evidence</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {sortedFindings.map((finding) => (
                <tr
                  key={finding.id}
                  onClick={() => setSelectedFinding(finding)}
                  className={`cursor-pointer transition-colors ${
                    selectedFinding?.id === finding.id
                      ? "bg-primary-soft/40"
                      : finding.state === "NOT-OBSERVABLE"
                      ? "bg-slate-50/60 hover:bg-slate-100"
                      : "hover:bg-slate-50"
                  }`}
                >
                  {/* Severity Badge */}
                  <td className="py-3.5 px-4">
                    <span
                      className={`inline-block rounded-md px-2 py-0.5 text-[10px] font-extrabold ${
                        finding.severity === "CRITICAL"
                          ? "bg-red-100 text-red-700 border border-red-200"
                          : finding.severity === "HIGH"
                          ? "bg-amber-50 text-amber-700 border border-amber-200"
                          : finding.severity === "MEDIUM"
                          ? "bg-amber-100 text-amber-700 border border-amber-200"
                          : "bg-blue-100 text-blue-700 border border-blue-200"
                      }`}
                    >
                      {finding.severity}
                    </span>
                  </td>

                  {/* Rule ID */}
                  <td className="py-3.5 px-3 font-mono font-bold text-slate-800">
                    {finding.ruleId}
                  </td>

                  {/* Title & CWE */}
                  <td className="py-3.5 px-4 max-w-md">
                    <div className="font-bold text-heading truncate">
                      {finding.ruleTitle}
                    </div>
                    <div className="text-[11px] text-muted truncate mt-0.5">
                      {finding.cwe}
                    </div>
                  </td>

                  {/* Observed Host */}
                  <td className="py-3.5 px-3 font-mono text-slate-700">
                    {finding.mxHost}
                  </td>

                  {/* Service */}
                  <td className="py-3.5 px-3 text-center font-mono font-semibold text-slate-600">
                    {finding.service}
                  </td>

                  {/* CVSS */}
                  <td className="py-3.5 px-3 text-center font-mono font-bold">
                    <span
                      className={
                        finding.cvss >= 9.0
                          ? "text-red-600"
                          : finding.cvss >= 7.0
                          ? "text-amber-600"
                          : finding.cvss > 0
                          ? "text-amber-600"
                          : "text-slate-400"
                      }
                    >
                      {finding.cvss.toFixed(1)}
                    </span>
                  </td>

                  {/* Confidence */}
                  <td className="py-3.5 px-3 text-center font-mono font-semibold">
                    <span
                      className={
                        finding.confidence >= 0.8
                          ? "text-emerald-700"
                          : "text-amber-700"
                      }
                    >
                      {(finding.confidence * 100).toFixed(0)}%
                    </span>
                  </td>

                  {/* Tri-state Badge (Never solid green for not-observable) */}
                  <td className="py-3.5 px-3">
                    <span
                      className={`inline-block rounded-md px-2 py-0.5 text-[10px] font-bold ${
                        finding.state === "VULNERABLE"
                          ? "bg-red-50 text-red-700 border border-red-200"
                          : finding.state === "SECURE"
                          ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                          : "bg-slate-200 text-slate-600 border border-slate-300"
                      }`}
                    >
                      {finding.state}
                    </span>
                  </td>

                  {/* Evidence CTA */}
                  <td className="py-3.5 px-4 text-right">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedFinding(finding);
                      }}
                      className="inline-flex items-center gap-1 font-bold text-primary hover:underline text-xs"
                    >
                      Inspect <ChevronRight className="h-3 w-3" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Evidence Drawer Overlay */}
      <EvidenceDrawer
        finding={selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
