"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  X,
  Hash,
  FileCode,
  CheckCircle2,
  Copy,
  ExternalLink,
  PlaySquare,
} from "lucide-react";
import { Finding } from "./DashboardContext";

interface EvidenceDrawerProps {
  finding: Finding | null;
  onClose: () => void;
}

export function EvidenceDrawer({ finding, onClose }: EvidenceDrawerProps) {
  const [copiedHash, setCopiedHash] = useState(false);

  if (!finding) return null;

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  return (
    <div className="fixed inset-y-0 right-0 z-50 flex w-full max-w-xl flex-col bg-white shadow-2xl border-l border-border animate-in slide-in-from-right duration-200">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border px-6 py-4">
        <div className="flex items-center gap-2">
          <span
            className={`rounded-md px-2 py-0.5 text-xs font-bold ${
              finding.severity === "CRITICAL"
                ? "bg-red-100 text-red-700"
                : finding.severity === "HIGH"
                ? "bg-amber-50 text-amber-700 border border-amber-200"
                : finding.severity === "MEDIUM"
                ? "bg-amber-100 text-amber-700"
                : "bg-blue-100 text-blue-700"
            }`}
          >
            {finding.severity}
          </span>
          <span className="font-mono text-xs font-bold text-slate-500">
            {finding.ruleId}
          </span>
        </div>
        <button
          onClick={onClose}
          className="rounded-lg p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700 transition-colors"
        >
          <X className="h-5 w-5" />
        </button>
      </div>

      {/* Body scroll area */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Title & Summary */}
        <div>
          <h2 className="text-xl font-bold text-heading">
            {finding.ruleTitle}
          </h2>
          <p className="mt-2 text-sm text-body leading-relaxed">
            {finding.summary}
          </p>
        </div>

        {/* Provenance Tuple (Core requirement from specs) */}
        <div className="rounded-2xl border border-border bg-surface-soft p-4">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-3 flex items-center gap-1.5">
            <Hash className="h-3.5 w-3.5 text-primary" />
            Packet-Level Provenance Tuple
          </div>
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div>
              <span className="text-muted block">Flow Identifier:</span>
              <span className="font-mono font-semibold text-slate-900 break-all">
                {finding.provenance.flowId}
              </span>
            </div>
            <div>
              <span className="text-muted block">Frame / Packet No:</span>
              <span className="font-mono font-semibold text-slate-900">
                #{finding.provenance.packetNo}
              </span>
            </div>
            <div>
              <span className="text-muted block">Packet Byte Offset:</span>
              <span className="font-mono font-bold text-primary">
                {finding.provenance.byteOffset}
              </span>
            </div>
            <div>
              <span className="text-muted block">TLS Record Index:</span>
              <span className="font-mono font-semibold text-slate-900">
                Record #{finding.provenance.tlsRecordIdx}
              </span>
            </div>
            <div>
              <span className="text-muted block">Captured Timestamp:</span>
              <span className="font-mono text-slate-700">
                {finding.provenance.timestamp}
              </span>
            </div>
            <div>
              <span className="text-muted block">Observed Host:</span>
              <span className="font-mono text-slate-700">
                {finding.mxHost}
              </span>
            </div>
          </div>
        </div>

        {/* Span Hash & Verification Link */}
        <div className="rounded-2xl border border-border bg-slate-900 text-white p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
              Span SHA-256 Receipt
            </span>
            <Link
              href="/dashboard/integrity"
              className="text-[11px] font-semibold text-cyan-400 hover:underline flex items-center gap-1"
            >
              Verify in Manifest <ExternalLink className="h-3 w-3" />
            </Link>
          </div>
          <div className="flex items-center justify-between rounded-lg bg-black/40 px-3 py-2 font-mono text-[11px] text-slate-300">
            <span className="truncate pr-2">{finding.provenance.spanHash}</span>
            <button
              onClick={() => copyToClipboard(finding.provenance.spanHash)}
              className="text-slate-400 hover:text-white transition-colors shrink-0"
              title="Copy hash"
            >
              {copiedHash ? (
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
              ) : (
                <Copy className="h-4 w-4" />
              )}
            </button>
          </div>
        </div>

        {/* Dual Hex / ASCII Packet Inspector */}
        <div>
          <div className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2 flex items-center gap-1.5">
            <FileCode className="h-3.5 w-3.5 text-primary" />
            Decoded Packet Wire Bytes
          </div>
          <div className="rounded-xl border border-border bg-slate-950 p-3.5 font-mono text-xs text-slate-200 space-y-2">
            <div>
              <span className="text-[10px] text-slate-500 block uppercase">Raw Hex Stream:</span>
              <p className="text-amber-400/90 break-all select-all leading-relaxed">
                {finding.provenance.hexSnippet}
              </p>
            </div>
            <div className="border-t border-slate-800 pt-2">
              <span className="text-[10px] text-slate-500 block uppercase">ASCII Inspection:</span>
              <p className="text-emerald-400 break-all select-all">
                {finding.provenance.asciiSnippet}
              </p>
            </div>
          </div>
        </div>

        {/* RFC / NIST Standard Clause Citation */}
        <div className="rounded-2xl border border-primary/20 bg-primary-soft/40 p-4">
          <div className="text-xs font-bold uppercase tracking-wider text-primary mb-1">
            Formal Protocol Specification Citation
          </div>
          <p className="text-xs text-slate-700 italic leading-relaxed">
            &quot;{finding.clause}&quot;
          </p>
          <div className="mt-3 flex items-center gap-4 text-xs font-medium text-slate-600">
            <span>CVSS Score: <strong className="text-slate-900">{finding.cvss}</strong></span>
            <span>Confidence: <strong className="text-slate-900">{(finding.confidence * 100).toFixed(0)}%</strong></span>
            <span>{finding.cwe}</span>
          </div>
        </div>
      </div>

      {/* Action Footer */}
      <div className="border-t border-border p-4 bg-slate-50 flex items-center justify-between">
        <Link
          href={`/dashboard/replay?finding=${finding.id}&flow=${finding.provenance.flowId}`}
          onClick={onClose}
          className="inline-flex items-center gap-2 rounded-xl bg-primary px-4 py-2.5 text-xs font-bold text-white hover:bg-primary-hover transition-colors shadow-sm"
        >
          <PlaySquare className="h-4 w-4" />
          Replay Flow in Forensic Inspector
        </Link>
        <button
          onClick={onClose}
          className="rounded-xl border border-border px-4 py-2.5 text-xs font-semibold text-slate-600 hover:bg-white transition-colors"
        >
          Close Drawer
        </button>
      </div>
    </div>
  );
}
