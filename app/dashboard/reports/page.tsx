"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  FileText,
  Download,
  Shield,
  CheckCircle2,
  Copy,
  Lock,
  ExternalLink,
  Terminal,
} from "lucide-react";
import { useDashboard } from "@/components/dashboard/DashboardContext";

export default function ReportsPage() {
  const { activeSession } = useDashboard();
  const [selectedMta, setSelectedMta] = useState<"postfix" | "exchange" | "exim">("postfix");
  const [copiedCode, setCopiedCode] = useState(false);

  const downloadJson = () => {
    const reportData = {
      sessionId: activeSession.id,
      timestamp: activeSession.date,
      score: activeSession.score,
      ci: [activeSession.ciLow, activeSession.ciHigh],
      grade: activeSession.grade,
      reportSha256Seal: activeSession.hash,
      packageVer: "1.4.0-sih",
      airGapped: true,
      findingsSummary: activeSession.findingsCount,
    };
    const blob = new Blob([JSON.stringify(reportData, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `raven_audit_report_${activeSession.id}.json`;
    a.click();
  };

  const copyConfig = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2000);
  };

  const postfixConfig = `# /etc/postfix/main.cf - Raven Hardened Cryptographic Baseline
# Remediates: SMS-ENF-002 (STARTTLS Stripping) & SMS-CIPH-001 (Sweet32 3DES)

# 1. Enforce Mandatory TLS with DANE & MTA-STS Pinning (rule_id: SMS-ENF-002)
smtp_tls_security_level = dane
smtp_tls_protocols = !SSLv2, !SSLv3, !TLSv1, !TLSv1.1
smtp_dns_support_level = dnssec

# 2. Inbound STARTTLS & Modern Cipher Capping (rule_id: SMS-CIPH-001)
smtpd_tls_security_level = may
smtpd_tls_mandatory_protocols = >=TLSv1.2
smtpd_tls_ciphers = high
smtpd_tls_exclude_ciphers = 3DES, DES, RC4, MD5, aNULL, eNULL

# 3. Log TLS Handshake Fingerprints for Passive Audit (rule_id: SMS-PROTO-001)
smtpd_tls_loglevel = 1`;

  const exchangeConfig = `# Microsoft Exchange Online / Edge Transport PowerShell Directives
# Remediates: SMS-ENF-002 & SMS-CIPH-001

# 1. Force Inbound/Outbound Strict TLS with Domain Pinning (rule_id: SMS-ENF-002)
Set-SendConnector -Identity "Outbound to Partner" -TlsDomain "partner.net" -TlsAuthLevel DomainValidation

# 2. Disable Legacy 3DES and RC4 Ciphers via Registry (rule_id: SMS-CIPH-001)
New-Item 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\Triple DES 168' -Force
Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Ciphers\\Triple DES 168' -Name 'Enabled' -Value 0`;

  const eximConfig = `# /etc/exim4/conf.d/main/01_raven_crypto - Exim Configuration
# Remediates: SMS-ENF-002 & SMS-CIPH-001

# 1. Mandatory TLS for Inbound SMTP (rule_id: SMS-ENF-002)
tls_advertise_hosts = *
tls_require_ciphers = SECURE256:SECURE128:-VERS-SSL3.0:-VERS-TLS1.0:-VERS-TLS1.1:-3DES:-RC4

# 2. Strict DANE Verification (rule_id: SMS-ENF-001)
dns_dnssec_enable = true`;

  return (
    <div className="space-y-8">
      {/* Title & Section Tag */}
      <div>
        <div className="inline-flex items-center gap-1.5 rounded-md bg-slate-100 px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider text-slate-700 mb-2">
          <FileText className="h-3.5 w-3.5 text-slate-600" />
          Audit Packaging & Remediation
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight text-heading">
          Cryptographic Reports & Playbooks
        </h1>
        <p className="mt-1 text-sm text-body">
          Self-contained, court-grade audit reports sealed with immutable SHA-256 signatures and vendor-tested remediation directives.
        </p>
      </div>

      {/* Export Bar & Report Seal (FR-33 & FR-34) */}
      <div className="grid gap-6 md:grid-cols-3">
        {/* Seal Card */}
        <div className="md:col-span-2 rounded-3xl border border-border bg-slate-950 p-6 text-white shadow-xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <Lock className="h-4 w-4 text-emerald-400" />
              <span className="font-mono text-xs font-bold uppercase tracking-wider text-slate-300">
                IMMUTABLE AUDIT REPORT SEAL
              </span>
            </div>
            <Link
              href="/dashboard/integrity"
              className="text-xs font-semibold text-cyan-400 hover:underline flex items-center gap-1"
            >
              Verify Chain in Manifest <ExternalLink className="h-3 w-3" />
            </Link>
          </div>

          <div className="space-y-2">
            <div className="text-xs text-slate-400">Cryptographic Root Digest:</div>
            <div className="rounded-xl bg-slate-900 border border-slate-800 p-3 font-mono text-xs text-emerald-400 break-all select-all">
              {activeSession.hash}
            </div>
          </div>

          <div className="grid grid-cols-3 gap-3 text-xs pt-2">
            <div>
              <span className="text-slate-400 block">Package Version:</span>
              <span className="font-mono font-bold text-white">v1.4.0-sih</span>
            </div>
            <div>
              <span className="text-slate-400 block">Posture Index:</span>
              <span className="font-mono font-bold text-primary">{activeSession.score}/100 [{activeSession.ciLow}–{activeSession.ciHigh}]</span>
            </div>
            <div>
              <span className="text-slate-400 block">Verdict Grade:</span>
              <span className="font-mono font-bold text-white">{activeSession.grade}</span>
            </div>
          </div>
        </div>

        {/* Export Bar Card */}
        <div className="rounded-3xl border border-border bg-white p-6 shadow-xs flex flex-col justify-between space-y-4">
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-heading flex items-center gap-2">
              <Download className="h-4 w-4 text-primary" />
              Export Audit Package
            </h3>
            <p className="text-xs text-muted mt-1 leading-relaxed">
              Export court-grade signed artifacts for DFIR examiners, compliance auditors, and SOC leads:
            </p>
          </div>

          <div className="space-y-2.5">
            <button
              onClick={downloadJson}
              className="flex w-full items-center justify-between rounded-xl border border-border bg-surface-soft px-4 py-2.5 text-xs font-bold text-slate-800 hover:bg-slate-100 transition-colors"
            >
              <span>Download JSON Evidence (.json)</span>
              <Download className="h-3.5 w-3.5 text-slate-400" />
            </button>
            <button
              onClick={() => alert("Generating standalone HTML audit bundle...")}
              className="flex w-full items-center justify-between rounded-xl border border-border bg-surface-soft px-4 py-2.5 text-xs font-bold text-slate-800 hover:bg-slate-100 transition-colors"
            >
              <span>Download Standalone HTML (.html)</span>
              <Download className="h-3.5 w-3.5 text-slate-400" />
            </button>
            <button
              onClick={() => alert("WeasyPrint rendering signed court-grade PDF...")}
              className="flex w-full items-center justify-between rounded-xl bg-primary px-4 py-2.5 text-xs font-bold text-white hover:bg-primary-hover transition-colors shadow-sm"
            >
              <span>Download Signed Audit PDF (.pdf)</span>
              <Download className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Remediation Playbook (FR-35: Rule-ID Keyed Deterministic Directives) */}
      <div className="rounded-3xl border border-border bg-white p-6 shadow-xs space-y-4">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 border-b border-border/60 pb-4">
          <div>
            <h3 className="text-base font-bold text-heading flex items-center gap-2">
              <Terminal className="h-4 w-4 text-primary" />
              Remediation Playbook (&quot;Fix Now&quot;)
            </h3>
            <p className="text-xs text-muted">
              Deterministic configuration templates keyed on observed findings. Every line ends with formal rule ID.
            </p>
          </div>

          {/* MTA Selector Tabs */}
          <div className="flex items-center gap-1 rounded-xl bg-surface-soft p-1 border border-border">
            <button
              onClick={() => setSelectedMta("postfix")}
              className={`rounded-lg px-3 py-1.5 text-xs font-bold transition-all ${
                selectedMta === "postfix" ? "bg-white text-primary shadow-xs" : "text-slate-600 hover:text-slate-900"
              }`}
            >
              Postfix MTA
            </button>
            <button
              onClick={() => setSelectedMta("exchange")}
              className={`rounded-lg px-3 py-1.5 text-xs font-bold transition-all ${
                selectedMta === "exchange" ? "bg-white text-primary shadow-xs" : "text-slate-600 hover:text-slate-900"
              }`}
            >
              MS Exchange
            </button>
            <button
              onClick={() => setSelectedMta("exim")}
              className={`rounded-lg px-3 py-1.5 text-xs font-bold transition-all ${
                selectedMta === "exim" ? "bg-white text-primary shadow-xs" : "text-slate-600 hover:text-slate-900"
              }`}
            >
              Exim MTA
            </button>
          </div>
        </div>

        {/* Code Snippet Box */}
        <div className="relative rounded-2xl bg-slate-950 p-5 font-mono text-xs text-slate-200 border border-slate-800">
          <button
            onClick={() =>
              copyConfig(
                selectedMta === "postfix"
                  ? postfixConfig
                  : selectedMta === "exchange"
                  ? exchangeConfig
                  : eximConfig
              )
            }
            className="absolute top-4 right-4 flex items-center gap-1.5 rounded-lg bg-slate-800 px-3 py-1 text-[11px] font-semibold text-slate-300 hover:bg-slate-700 transition-colors"
          >
            {copiedCode ? (
              <>
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                <span>Copied</span>
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5" />
                <span>Copy Directive</span>
              </>
            )}
          </button>

          <pre className="overflow-x-auto leading-relaxed text-slate-300 pt-2">
            {selectedMta === "postfix"
              ? postfixConfig
              : selectedMta === "exchange"
              ? exchangeConfig
              : eximConfig}
          </pre>
        </div>
      </div>

      {/* Hardening Roadmap ("Stay Ahead" per FR-36) */}
      <div className="rounded-3xl border border-border bg-white p-6 shadow-xs space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-bold text-heading flex items-center gap-2">
            <Shield className="h-4 w-4 text-emerald-600" />
            Cryptographic Hardening Roadmap (&quot;Stay Ahead&quot;)
          </h3>
          <span className="text-xs font-mono text-muted">NIST SP 800-52r2 Aligned</span>
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <div className="rounded-2xl border border-border bg-surface-soft p-4 space-y-2">
            <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-700 bg-emerald-100 px-2 py-0.5 rounded-md">
              Phase 1 · Immediate
            </span>
            <h4 className="text-xs font-bold text-heading">
              Enforce MTA-STS &quot;mode=enforce&quot;
            </h4>
            <p className="text-xs text-muted leading-relaxed">
              Transition DNS TXT record from testing to enforce. Eliminates silent downgrade vulnerabilities over public MX relays (rule_id: SMS-ENF-001).
            </p>
          </div>

          <div className="rounded-2xl border border-border bg-surface-soft p-4 space-y-2">
            <span className="text-[10px] font-bold uppercase tracking-wider text-blue-700 bg-blue-100 px-2 py-0.5 rounded-md">
              Phase 2 · 30 Days
            </span>
            <h4 className="text-xs font-bold text-heading">
              Deploy DANE TLSA with DNSSEC
            </h4>
            <p className="text-xs text-muted leading-relaxed">
              Publish port 25 TLSA certificate association records to bind cryptographic certificates directly to DNS root anchors (rule_id: SMS-ENF-003).
            </p>
          </div>

          <div className="rounded-2xl border border-border bg-surface-soft p-4 space-y-2">
            <span className="text-[10px] font-bold uppercase tracking-wider text-purple-700 bg-purple-100 px-2 py-0.5 rounded-md">
              Phase 3 · Post-Quantum
            </span>
            <h4 className="text-xs font-bold text-heading">
              PQC / CNSA-2 Hybrid Readiness
            </h4>
            <p className="text-xs text-muted leading-relaxed">
              Audit support for ML-KEM / X25519 hybrid key exchange groups to prevent harvest-now-decrypt-later adversaries (rule_id: SMS-KEY-005).
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
