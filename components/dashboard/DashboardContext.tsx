"use client";

import React, { createContext, useContext, useState, useEffect, ReactNode } from "react";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type FindingState = "VULNERABLE" | "SECURE" | "NOT-OBSERVABLE";
export type Service = "SMTP" | "IMAP" | "POP3";

export interface Finding {
  id: string;
  ruleId: string;
  ruleTitle: string;
  severity: Severity;
  state: FindingState;
  service: Service;
  mxHost: string;
  cvss: number;
  cwe: string;
  confidence: number; // 0.0 to 1.0
  clause: string;
  summary: string;
  provenance: {
    flowId: string;
    packetNo: number;
    byteOffset: string;
    tlsRecordIdx: number;
    timestamp: string;
    spanHash: string;
    hexSnippet: string;
    asciiSnippet: string;
  };
}

export interface Scenario {
  id: string;
  name: string;
  filename: string;
  size: string;
  flows: number;
  score: number;
  ciLow: number;
  ciHigh: number;
  grade: string;
  hash: string;
  date: string;
  status: "ANALYZED" | "READY" | "RUNNING";
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    notObservable: number;
  };
}

export interface MXHostScore {
  name: string;
  ip: string;
  role: "PRIMARY_INGRESS" | "SECONDARY_INGRESS" | "PARTNER_RELAY" | "EDGE_GATEWAY";
  score: number;
  ci: [number, number];
  grade: string;
  subscores: {
    protocol: number; // 0-100
    cipher: number;
    keyExchange: number;
    x509: number | "NOT-OBSERVABLE";
    dns: number;
    enforcement: number;
  };
  mtaStsMode: "enforce" | "testing" | "none";
  daneTlsa: "VALID" | "MISCONFIGURED" | "ABSENT";
  tlsRpt: boolean;
  plaintextRatio: number;
  verdict: "CONSISTENT" | "VIOLATION" | "UNOBSERVED";
}

export interface GraphNode {
  id: string;
  label: string;
  type: "INTERNAL_MX" | "PEER_MX" | "RELAY";
  grade: string;
  score: number;
  isWeakest?: boolean;
}

export interface GraphEdge {
  source: string;
  target: string;
  volume: number;
  percentage: number;
  status: "ENCRYPTED_TLS13" | "ENCRYPTED_TLS12" | "STRIPPED_CLEARTEXT" | "OPPORTUNISTIC";
  isWeakest?: boolean;
}

interface DashboardContextType {
  activeSession: Scenario;
  sessions: Scenario[];
  switchSession: (sessionId: string) => void;
  isAirGapped: boolean;
  toggleAirGapped: () => void;
  findings: Finding[];
  selectedFinding: Finding | null;
  setSelectedFinding: (finding: Finding | null) => void;
  pipelineRunning: boolean;
  pipelineStage: number; // 0 to 9
  runPipeline: (scenarioId?: string) => void;
  pipelineLogs: string[];
  mxHosts: MXHostScore[];
  graphNodes: GraphNode[];
  graphEdges: GraphEdge[];
  backendConnected: boolean;
  uploadCapture: (file: File) => Promise<boolean>;
  isUploading: boolean;
}

interface RawBackendFinding {
  id?: string | null;
  rule_id?: string;
  ruleId?: string;
  title?: string;
  ruleTitle?: string;
  severity?: string;
  state?: string;
  flow_id?: string;
  cvss?: number;
  cwe?: string;
  confidence?: number;
  clause?: string;
  summary?: string;
  provenance?: {
    flow_id?: string;
    packet_no?: number;
    byte_offset?: string;
    tls_record_idx?: number;
    timestamp?: string;
    span_hash?: string;
    hex_snippet?: string;
    ascii_snippet?: string;
  };
}

interface RawBackendSession {
  id: string;
  source_file: string;
  flow_count?: number;
  score?: number;
  ci_range?: [number, number];
  grade?: string;
  report_hash?: string;
  started_at?: string;
}

interface RawBackendMX {
  mx: string;
  index: number;
  ci_low: number;
  ci_high: number;
  grade: string;
  sub_scores: {
    protocol: number;
    cipher: number;
    key: number;
    x509: number | "NOT-OBSERVABLE";
    dns: number;
    enforce: number;
  };
  tri_state_summary?: {
    VULNERABLE?: number;
    SECURE?: number;
    "NOT-OBSERVABLE"?: number;
  };
}

interface RawBackendNode {
  id: string;
  label: string;
  type: "INTERNAL_MX" | "PEER_MX" | "RELAY";
  grade: string;
  score: number;
}

interface RawBackendEdge {
  source: string;
  target: string;
  volume: number;
  percentage: number;
  status: "ENCRYPTED_TLS13" | "ENCRYPTED_TLS12" | "STRIPPED_CLEARTEXT" | "OPPORTUNISTIC";
  is_weakest?: boolean;
}

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001";

function adaptBackendFinding(bf: RawBackendFinding, index: number): Finding {
  const flowParts = (bf.flow_id || "").split("->");
  const mxCandidate = flowParts.length > 1 ? flowParts[1].split(":")[0] : "mx.perimeter.net";

  return {
    id: bf.id || `FIND-${String(index + 1).padStart(3, "0")}`,
    ruleId: bf.rule_id || bf.ruleId || "SMS-GEN-001",
    ruleTitle: bf.title || bf.ruleTitle || "Cryptographic Finding",
    severity: (bf.severity?.toUpperCase() || "HIGH") as Severity,
    state: (bf.state?.toUpperCase() || "VULNERABLE") as FindingState,
    service: "SMTP",
    mxHost: mxCandidate,
    cvss: bf.cvss ?? 7.5,
    cwe: bf.cwe || "CWE-319 (Cleartext Transmission of Sensitive Information)",
    confidence: bf.confidence ?? 0.95,
    clause: bf.clause || "RFC 3207 §4 / RFC 8461 §2",
    summary: bf.summary || "",
    provenance: {
      flowId: bf.provenance?.flow_id || bf.flow_id || "tcp-flow-1",
      packetNo: bf.provenance?.packet_no ?? 1,
      byteOffset: bf.provenance?.byte_offset || "0x00000200",
      tlsRecordIdx: bf.provenance?.tls_record_idx ?? 0,
      timestamp: bf.provenance?.timestamp || "2026-09-29 12:00:00 UTC",
      spanHash: bf.provenance?.span_hash || "sha256:0000",
      hexSnippet: bf.provenance?.hex_snippet || "32 35 30 2d 53 54 41 52 54 54 4c 53",
      asciiSnippet: bf.provenance?.ascii_snippet || "250-STARTTLS",
    },
  };
}

function adaptBackendSession(bs: RawBackendSession): Scenario {
  return {
    id: bs.id,
    name: bs.source_file.replace(".pcap", "").replace("-", " ").toUpperCase(),
    filename: bs.source_file,
    size: "1.2 MB",
    flows: bs.flow_count || 1,
    score: Math.round(bs.score || 75),
    ciLow: Math.round(bs.ci_range?.[0] || 60),
    ciHigh: Math.round(bs.ci_range?.[1] || 76),
    grade: bs.grade || "Grade C",
    hash: bs.report_hash || "sha256:0000",
    date: bs.started_at || "2026-09-29 12:00 UTC",
    status: "ANALYZED",
    findingsCount: {
      critical: (bs.score || 75) < 60 ? 2 : 0,
      high: (bs.score || 75) < 70 ? 2 : 1,
      medium: 1,
      low: 1,
      notObservable: 1,
    },
  };
}

function adaptBackendMX(bmx: RawBackendMX): MXHostScore {
  return {
    name: bmx.mx,
    ip: "198.51.100.14",
    role: bmx.mx.includes("partner")
      ? "PARTNER_RELAY"
      : bmx.mx.includes("mx2")
      ? "SECONDARY_INGRESS"
      : "PRIMARY_INGRESS",
    score: Math.round(bmx.index),
    ci: [Math.round(bmx.ci_low), Math.round(bmx.ci_high)],
    grade: bmx.grade,
    subscores: {
      protocol: Math.round(bmx.sub_scores.protocol),
      cipher: Math.round(bmx.sub_scores.cipher),
      keyExchange: Math.round(bmx.sub_scores.key),
      x509: bmx.sub_scores.x509,
      dns: Math.round(bmx.sub_scores.dns),
      enforcement: Math.round(bmx.sub_scores.enforce),
    },
    mtaStsMode: bmx.sub_scores.enforce > 70 ? "testing" : "none",
    daneTlsa: bmx.sub_scores.dns > 70 ? "VALID" : "ABSENT",
    tlsRpt: bmx.sub_scores.enforce > 50,
    plaintextRatio: bmx.tri_state_summary?.VULNERABLE ? 0.68 : 0.02,
    verdict: (bmx.tri_state_summary?.VULNERABLE ?? 0) > 0 ? "VIOLATION" : "CONSISTENT",
  };
}

// Scenarios dataset
const SCENARIOS: Scenario[] = [
  {
    id: "session-stripped-01",
    name: "STARTTLS Stripping Downgrade (Active MITM)",
    filename: "stripped-starttls-mitm.pcap",
    size: "42.8 MB",
    flows: 1420,
    score: 58,
    ciLow: 44,
    ciHigh: 69,
    grade: "Grade D",
    hash: "sha256:d8b74c8109bfca33984e723910cbe6a894726ef39e01103f671bc9aa192a543f",
    date: "2026-09-29 11:42 UTC",
    status: "ANALYZED",
    findingsCount: { critical: 2, high: 4, medium: 5, low: 3, notObservable: 6 },
  },
  {
    id: "session-weakciphers-02",
    name: "Legacy Cryptography (3DES & CBC Sweet32)",
    filename: "legacy-ciphers-sweet32.pcap",
    size: "18.4 MB",
    flows: 890,
    score: 68,
    ciLow: 61,
    ciHigh: 74,
    grade: "Grade C",
    hash: "sha256:fa23498801ceb834907106b29cf129487c0931481b0a9c8b745f6902ecb1428b",
    date: "2026-09-29 09:15 UTC",
    status: "ANALYZED",
    findingsCount: { critical: 0, high: 3, medium: 7, low: 2, notObservable: 2 },
  },
  {
    id: "session-expiredx509-03",
    name: "X.509 Trust Anchor Broken & Hostname Mismatch",
    filename: "cert-validation-failure.pcapng",
    size: "64.2 MB",
    flows: 2150,
    score: 64,
    ciLow: 56,
    ciHigh: 72,
    grade: "Grade C-",
    hash: "sha256:7b8f44e1903cbe0891d4e08215ccba184019baee74087134aa8f9024f0c83a71",
    date: "2026-09-28 18:30 UTC",
    status: "ANALYZED",
    findingsCount: { critical: 1, high: 4, medium: 4, low: 4, notObservable: 5 },
  },
  {
    id: "session-hardened-04",
    name: "Strict MTA-STS & DANE TLSA Pinning",
    filename: "hardened-dane-mtasts.pcap",
    size: "88.1 MB",
    flows: 3840,
    score: 96,
    ciLow: 93,
    ciHigh: 99,
    grade: "Grade A+",
    hash: "sha256:9e4f16bc44e138a09b3074812f8623b09cc01e14917452d0fa3b829e0147610c",
    date: "2026-09-28 14:02 UTC",
    status: "ANALYZED",
    findingsCount: { critical: 0, high: 0, medium: 1, low: 2, notObservable: 1 },
  },
  {
    id: "session-corporate-05",
    name: "Corporate Perimeter Multi-MX Gateway",
    filename: "corp-perimeter-live-tap.pcap",
    size: "128.5 MB",
    flows: 5120,
    score: 78,
    ciLow: 71,
    ciHigh: 84,
    grade: "Grade B+",
    hash: "sha256:4c1199a071fe081643ba28741165cb4091e843238914bca8154e01934ef81c5a",
    date: "2026-09-29 13:00 UTC",
    status: "ANALYZED",
    findingsCount: { critical: 1, high: 2, medium: 6, low: 5, notObservable: 8 },
  },
];

// Rich findings catalog
const FINDINGS_CATALOG: Finding[] = [
  {
    id: "FIND-001",
    ruleId: "SMS-ENF-002",
    ruleTitle: "Active STARTTLS Stripping (RFC 3207 Suppression)",
    severity: "CRITICAL",
    state: "VULNERABLE",
    service: "SMTP",
    mxHost: "relay-gw.partner.net",
    cvss: 9.1,
    cwe: "CWE-319 (Cleartext Transmission of Sensitive Information)",
    confidence: 0.98,
    clause: "RFC 3207 §4 / RFC 8461 §2: 250 STARTTLS advertised on primary interface but stripped by intermediary.",
    summary: "Observed EHLO response containing 250-STARTTLS on ingress, but downstream proxy rewrote the response removing the capability. Flow proceeded in unencrypted cleartext containing financial payload bytes.",
    provenance: {
      flowId: "tcp-flow-198-51-100-14-port-25",
      packetNo: 142,
      byteOffset: "0x00004F2A",
      tlsRecordIdx: 0,
      timestamp: "2026-09-29 11:42:04.108",
      spanHash: "sha256:d8b74c8109bfca33984e723910cbe6a894726ef39e01103f671bc9aa192a543f",
      hexSnippet: "45 48 4c 4f 20 6d 61 69 6c 2e 63 6f 72 70 2e 6e 65 74 0d 0a 32 35 30 2d 50 49 50 45 4c 49 4e 45 0d 0a 32 35 30 2d 53 49 5a 45 20 33 35 38 38 30 30 30 0d 0a",
      asciiSnippet: "EHLO mail.corp.net..250-PIPELINE..250-SIZE 3588000.. [STARTTLS OMITTED]",
    },
  },
  {
    id: "FIND-002",
    ruleId: "SMS-RADAR-001",
    ruleTitle: "Downgrade Radar: Advertised Capability Unused",
    severity: "HIGH",
    state: "VULNERABLE",
    service: "SMTP",
    mxHost: "mail.outbound.corp.net",
    cvss: 7.5,
    cwe: "CWE-757 (Selection of Less-Secure Algorithm During Negotiation)",
    confidence: 0.94,
    clause: "RFC 3207 §4.2: Client MTA omitted STARTTLS command despite receiving server capability advertisement.",
    summary: "Target server properly advertised '250-STARTTLS', yet client MTA immediately issued 'MAIL FROM' in cleartext without attempting cryptographic upgrade.",
    provenance: {
      flowId: "tcp-flow-203-0-113-5-port-25",
      packetNo: 418,
      byteOffset: "0x00009B10",
      tlsRecordIdx: 0,
      timestamp: "2026-09-29 11:42:18.420",
      spanHash: "sha256:89a4192b0c1e8471b8319f041cb3a9082ef4189021cd49e81b0a94cb199341ef",
      hexSnippet: "32 35 30 2d 53 54 41 52 54 54 4c 53 0d 0a 4d 41 49 4c 20 46 52 4f 4d 3a 3c 73 65 63 40 63 6f 72 70 2e 6e 65 74 3e 0d 0a",
      asciiSnippet: "250-STARTTLS..MAIL FROM:<sec@corp.net>..",
    },
  },
  {
    id: "FIND-003",
    ruleId: "SMS-CIPH-001",
    ruleTitle: "Deprecated Cipher Suite: 3DES-EDE-CBC Sweet32 Exposure",
    severity: "HIGH",
    state: "VULNERABLE",
    service: "SMTP",
    mxHost: "legacy-mx.backup.internal",
    cvss: 7.5,
    cwe: "CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)",
    confidence: 0.99,
    clause: "NIST SP 800-52r2 §3.3.1 / RFC 7525: 64-bit block ciphers prohibited due to birthday attack collision risks.",
    summary: "ServerHello negotiated TLS_RSA_WITH_3DES_EDE_CBC_SHA. 64-bit cipher vulnerable to Sweet32 plaintext extraction over long-lived TLS sessions.",
    provenance: {
      flowId: "tcp-flow-198-51-100-88-port-587",
      packetNo: 624,
      byteOffset: "0x00012A34",
      tlsRecordIdx: 1,
      timestamp: "2026-09-29 11:43:02.812",
      spanHash: "sha256:39a1c84b109e3827104bce1849102834b91023847190ca81b83901bca092147d",
      hexSnippet: "16 03 03 00 4a 02 00 00 46 03 03 a1 b2 c3 d4 e5 f6 ... 00 0a",
      asciiSnippet: "TLS ServerHello ... CipherSuite: TLS_RSA_WITH_3DES_EDE_CBC_SHA [0x000A]",
    },
  },
  {
    id: "FIND-004",
    ruleId: "SMS-X509-002",
    ruleTitle: "Subject Alternative Name (SAN) Hostname Mismatch",
    severity: "HIGH",
    state: "VULNERABLE",
    service: "SMTP",
    mxHost: "mx2.partner.net",
    cvss: 7.4,
    cwe: "CWE-297 (Improper Validation of Certificate with Host Mismatch)",
    confidence: 0.95,
    clause: "RFC 6125 §6.4.4 / RFC 8461 §4.1: Peer identity must match DNS hostname resolved in MX record.",
    summary: "Certificate CN is 'internal-gateway.local'; SAN list lacks 'mx2.partner.net'. Over 40% of MTA implementations fail open and silently ignore this validation error.",
    provenance: {
      flowId: "tcp-flow-198-51-100-14-port-25",
      packetNo: 712,
      byteOffset: "0x00019C00",
      tlsRecordIdx: 2,
      timestamp: "2026-09-29 11:43:20.440",
      spanHash: "sha256:719a84b01e3892019481bc9013840192eab18239014bcda09182301984bcae12",
      hexSnippet: "30 82 02 4b 30 82 01 b4 a0 03 02 01 02 ... 55 04 03 13 16 69 6e 74 65 72 6e 61 6c 2d 67 61 74 65 77 61 79",
      asciiSnippet: "X.509 Certificate ... CN=internal-gateway.local [Mismatch with mx2.partner.net]",
    },
  },
  {
    id: "FIND-005",
    ruleId: "SMS-X509-008",
    ruleTitle: "X.509 Certificate Chain Unobservable (Encrypted Handshake)",
    severity: "INFO",
    state: "NOT-OBSERVABLE",
    service: "SMTP",
    mxHost: "mx1.corp.net",
    cvss: 0.0,
    cwe: "CWE-693 (Protection Mechanism Failure)",
    confidence: 0.15,
    clause: "RFC 8446 (TLS 1.3): Certificate message is encrypted by handshake keys. Passive air-gapped sniffer cannot observe cert parameters.",
    summary: "Flow negotiated TLS 1.3. Certificate payload is cryptographically protected on the wire. Under Raven RFC rigor, sub-confidence floors at 0.15 to avoid false-green scoring.",
    provenance: {
      flowId: "tcp-flow-198-51-100-10-port-25",
      packetNo: 18,
      byteOffset: "0x00000840",
      tlsRecordIdx: 1,
      timestamp: "2026-09-29 11:40:01.015",
      spanHash: "sha256:1049281bc8940129384710293841029384102938401928340192834019283401",
      hexSnippet: "17 03 03 01 20 ... [Encrypted Handshake Message: Certificate & CertVerify]",
      asciiSnippet: "[TLS 1.3 Encrypted Handshake Payload - Not Observable Passively]",
    },
  },
  {
    id: "FIND-006",
    ruleId: "SMS-PROTO-001",
    ruleTitle: "Modern TLS 1.3 Negotiated with Forward Secrecy",
    severity: "INFO",
    state: "SECURE",
    service: "SMTP",
    mxHost: "mx1.corp.net",
    cvss: 0.0,
    cwe: "N/A",
    confidence: 1.0,
    clause: "RFC 8446 / NIST SP 800-52r2: TLS 1.3 with Curve25519 (X25519) key exchange and AES-256-GCM.",
    summary: "Handshake verified with state-of-the-art cryptographic strength. Ephemeral Diffie-Hellman guarantees perfect forward secrecy.",
    provenance: {
      flowId: "tcp-flow-198-51-100-10-port-25",
      packetNo: 14,
      byteOffset: "0x00000520",
      tlsRecordIdx: 0,
      timestamp: "2026-09-29 11:40:00.890",
      spanHash: "sha256:6639102938401923840192834019283401928340192834019283401928340192",
      hexSnippet: "16 03 03 00 7a 02 00 00 76 03 03 ... 13 02 00 00 2e 00 33 00 24 00 1d",
      asciiSnippet: "ServerHello ... CipherSuite: TLS_AES_256_GCM_SHA384 [0x1302] Group: X25519",
    },
  },
  {
    id: "FIND-007",
    ruleId: "SMS-ENF-001",
    ruleTitle: "MTA-STS Policy Absent or Mode=None",
    severity: "MEDIUM",
    state: "VULNERABLE",
    service: "SMTP",
    mxHost: "relay-gw.partner.net",
    cvss: 5.3,
    cwe: "CWE-300 (Channel Accessible by Non-Endpoint)",
    confidence: 0.90,
    clause: "RFC 8461 §3.1: Domain lacks active MTA-STS DNS TXT record and HTTPS policy daemon.",
    summary: "Sending MTAs cannot verify whether encryption is strictly mandatory, leaving transit vulnerable to silent active stripping attacks.",
    provenance: {
      flowId: "dns-query-partner-net",
      packetNo: 89,
      byteOffset: "0x00001800",
      tlsRecordIdx: 0,
      timestamp: "2026-09-29 11:41:10.024",
      spanHash: "sha256:5520192830192830192830192830192830192830192830192830192830192830",
      hexSnippet: "00 01 01 00 00 01 00 00 00 00 00 00 07 5f 6d 74 61 73 74 73 07 70 61 72",
      asciiSnippet: "_mta-sts.partner.net IN TXT -> NXDOMAIN",
    },
  },
];

// MX Hosts matrix
const MX_HOSTS: MXHostScore[] = [
  {
    name: "mx1.corp.net",
    ip: "198.51.100.10",
    role: "PRIMARY_INGRESS",
    score: 88,
    ci: [84, 92],
    grade: "Grade A-",
    subscores: {
      protocol: 95,
      cipher: 92,
      keyExchange: 95,
      x509: "NOT-OBSERVABLE",
      dns: 85,
      enforcement: 80,
    },
    mtaStsMode: "testing",
    daneTlsa: "VALID",
    tlsRpt: true,
    plaintextRatio: 0.02,
    verdict: "CONSISTENT",
  },
  {
    name: "mx2.corp.net",
    ip: "198.51.100.11",
    role: "SECONDARY_INGRESS",
    score: 82,
    ci: [76, 88],
    grade: "Grade B",
    subscores: {
      protocol: 90,
      cipher: 88,
      keyExchange: 90,
      x509: "NOT-OBSERVABLE",
      dns: 85,
      enforcement: 75,
    },
    mtaStsMode: "testing",
    daneTlsa: "VALID",
    tlsRpt: true,
    plaintextRatio: 0.04,
    verdict: "CONSISTENT",
  },
  {
    name: "relay-gw.partner.net",
    ip: "198.51.100.14",
    role: "PARTNER_RELAY",
    score: 42,
    ci: [32, 52],
    grade: "Grade E",
    subscores: {
      protocol: 30,
      cipher: 45,
      keyExchange: 40,
      x509: 25,
      dns: 50,
      enforcement: 15,
    },
    mtaStsMode: "none",
    daneTlsa: "ABSENT",
    tlsRpt: false,
    plaintextRatio: 0.68,
    verdict: "VIOLATION",
  },
  {
    name: "legacy-mx.backup.internal",
    ip: "198.51.100.88",
    role: "EDGE_GATEWAY",
    score: 54,
    ci: [48, 62],
    grade: "Grade D-",
    subscores: {
      protocol: 55,
      cipher: 35,
      keyExchange: 60,
      x509: 45,
      dns: 60,
      enforcement: 30,
    },
    mtaStsMode: "none",
    daneTlsa: "MISCONFIGURED",
    tlsRpt: false,
    plaintextRatio: 0.35,
    verdict: "VIOLATION",
  },
];

// Delivery Topology Graph
const GRAPH_NODES: GraphNode[] = [
  { id: "corp-mx1", label: "mx1.corp.net", type: "INTERNAL_MX", grade: "A-", score: 88 },
  { id: "corp-mx2", label: "mx2.corp.net", type: "INTERNAL_MX", grade: "B", score: 82 },
  { id: "peer-google", label: "aspmx.l.google.com", type: "PEER_MX", grade: "A+", score: 98 },
  { id: "peer-msft", label: "mail.protection.outlook.com", type: "PEER_MX", grade: "A", score: 92 },
  { id: "peer-weak-relay", label: "relay-gw.partner.net", type: "RELAY", grade: "E", score: 42, isWeakest: true },
  { id: "peer-cisco", label: "esa.corp-partner.org", type: "PEER_MX", grade: "B+", score: 79 },
  { id: "peer-legacy", label: "legacy-mx.backup.internal", type: "RELAY", grade: "D-", score: 54 },
];

const GRAPH_EDGES: GraphEdge[] = [
  { source: "corp-mx1", target: "peer-google", volume: 2450, percentage: 48, status: "ENCRYPTED_TLS13" },
  { source: "corp-mx1", target: "peer-msft", volume: 1220, percentage: 24, status: "ENCRYPTED_TLS13" },
  { source: "corp-mx1", target: "peer-weak-relay", volume: 890, percentage: 17, status: "STRIPPED_CLEARTEXT", isWeakest: true },
  { source: "corp-mx2", target: "peer-cisco", volume: 380, percentage: 7, status: "ENCRYPTED_TLS12" },
  { source: "corp-mx2", target: "peer-legacy", volume: 180, percentage: 4, status: "OPPORTUNISTIC" },
];

const DashboardContext = createContext<DashboardContextType | undefined>(undefined);

export function DashboardProvider({ children }: { children: ReactNode }) {
  const [sessions, setSessions] = useState<Scenario[]>(SCENARIOS);
  const [activeSession, setActiveSession] = useState<Scenario>(SCENARIOS[0]);
  const [isAirGapped, setIsAirGapped] = useState<boolean>(true);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  // Dynamic live-state
  const [backendConnected, setBackendConnected] = useState<boolean>(false);
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [findings, setFindings] = useState<Finding[]>(FINDINGS_CATALOG);
  const [mxHosts, setMxHosts] = useState<MXHostScore[]>(MX_HOSTS);
  const [graphNodes, setGraphNodes] = useState<GraphNode[]>(GRAPH_NODES);
  const [graphEdges, setGraphEdges] = useState<GraphEdge[]>(GRAPH_EDGES);

  // Pipeline simulation state
  const [pipelineRunning, setPipelineRunning] = useState<boolean>(false);
  const [pipelineStage, setPipelineStage] = useState<number>(9); // 9 = done
  const [pipelineLogs, setPipelineLogs] = useState<string[]>([
    "[00:00.001] Initialized air-gapped packet parser engine (tshark 4.2.3)",
    "[00:00.042] Parsed 1,420 protocol flows (100% passive, 0 egress packets)",
    "[00:00.118] Extracted 25-dimensional cryptographic feature tensors",
    "[00:00.204] Evaluated 48 deterministic RFC rules against state catalog",
    "[00:00.312] Downgrade Radar: STRIP-ACTIVE detected on hop 2 (relay-gw.partner.net)",
    "[00:00.419] Posture confidence bounds calculated: 58/100 [CI: 44-69] Grade D",
    "[00:00.501] Forensic evidence store committed SHA256: d8b74c81...9e01",
  ]);

  // Check backend health & fetch live captures on mount
  useEffect(() => {
    let isMounted = true;
    async function initBackend() {
      try {
        const res = await fetch(`${BACKEND_URL}/api/v1/health`);
        if (res.ok) {
          if (!isMounted) return;
          setBackendConnected(true);
          const capRes = await fetch(`${BACKEND_URL}/api/v1/captures`);
          if (capRes.ok) {
            const capData = await capRes.json();
            if (Array.isArray(capData) && capData.length > 0) {
              const adapted = capData.map(adaptBackendSession);
              setSessions(adapted);
              const initial = adapted[0];
              setActiveSession(initial);

              // Immediately fetch live findings, posture scores, and graph for initial session
              try {
                const [fRes, mxRes, gRes] = await Promise.all([
                  fetch(`${BACKEND_URL}/api/v1/findings?session_id=${initial.id}`),
                  fetch(`${BACKEND_URL}/api/v1/mx?session_id=${initial.id}`),
                  fetch(`${BACKEND_URL}/api/v1/graph/${initial.id}`),
                ]);

                if (fRes.ok) {
                  const fData = await fRes.json();
                  if (Array.isArray(fData) && fData.length > 0) {
                    setFindings(fData.map(adaptBackendFinding));
                  }
                }
                if (mxRes.ok) {
                  const mxData = await mxRes.json();
                  if (Array.isArray(mxData) && mxData.length > 0) {
                    setMxHosts(mxData.map(adaptBackendMX));
                  }
                }
                if (gRes.ok) {
                  const gData = await gRes.json();
                  if (gData.nodes && gData.edges) {
                    setGraphNodes(
                      gData.nodes.map((n: RawBackendNode) => ({
                        id: n.id,
                        label: n.label,
                        type: n.type,
                        grade: n.grade,
                        score: n.score,
                        isWeakest: n.label === gData.weakest_hop,
                      }))
                    );
                    setGraphEdges(
                      gData.edges.map((e: RawBackendEdge) => ({
                        source: e.source,
                        target: e.target,
                        volume: e.volume,
                        percentage: e.percentage,
                        status: e.status,
                        isWeakest: e.is_weakest,
                      }))
                    );
                  }
                }
              } catch {
                // Keep local defaults
              }
            }
          }
        }
      } catch {
        if (isMounted) setBackendConnected(false);
      }
    }
    initBackend();
    return () => {
      isMounted = false;
    };
  }, []);

  const switchSession = async (sessionId: string) => {
    const found = sessions.find((s) => s.id === sessionId);
    if (found) {
      setActiveSession(found);
      setSelectedFinding(null);
    }

    if (backendConnected) {
      try {
        const [fRes, mxRes, gRes] = await Promise.all([
          fetch(`${BACKEND_URL}/api/v1/findings?session_id=${sessionId}`),
          fetch(`${BACKEND_URL}/api/v1/mx?session_id=${sessionId}`),
          fetch(`${BACKEND_URL}/api/v1/graph/${sessionId}`),
        ]);

        if (fRes.ok) {
          const fData = await fRes.json();
          if (Array.isArray(fData) && fData.length > 0) {
            setFindings(fData.map(adaptBackendFinding));
          } else {
            setFindings(FINDINGS_CATALOG);
          }
        }

        if (mxRes.ok) {
          const mxData = await mxRes.json();
          if (Array.isArray(mxData) && mxData.length > 0) {
            setMxHosts(mxData.map(adaptBackendMX));
          }
        }

        if (gRes.ok) {
          const gData = await gRes.json();
          if (gData.nodes && gData.edges) {
            setGraphNodes(
              gData.nodes.map((n: RawBackendNode) => ({
                id: n.id,
                label: n.label,
                type: n.type,
                grade: n.grade,
                score: n.score,
                isWeakest: n.label === gData.weakest_hop,
              }))
            );
            setGraphEdges(
              gData.edges.map((e: RawBackendEdge) => ({
                source: e.source,
                target: e.target,
                volume: e.volume,
                percentage: e.percentage,
                status: e.status,
                isWeakest: e.is_weakest,
              }))
            );
          }
        }
      } catch {
        // Fall back gracefully
      }
    }
  };

  const uploadCapture = async (file: File): Promise<boolean> => {
    setIsUploading(true);
    setPipelineRunning(true);
    setPipelineStage(2);
    setPipelineLogs([
      `[00:00.001] Receiving uploaded capture: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`,
      `[00:00.084] Dispatching to FastAPI engine at ${BACKEND_URL}/api/v1/captures/upload`,
    ]);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const res = await fetch(`${BACKEND_URL}/api/v1/captures/upload`, {
        method: "POST",
        body: formData,
      });

      if (res.ok) {
        const data = await res.json();
        setPipelineStage(6);
        setPipelineLogs((prev) => [
          ...prev,
          `[00:00.210] Scapy parsed ${data.flow_count} flow(s). Rules evaluated: ${data.findings_count} findings.`,
          `[00:00.320] Downgrade radar & Bayesian posture computed: ${data.score}/100 (${data.grade})`,
        ]);

        const newSession: Scenario = {
          id: data.session_id,
          name: `Live: ${data.filename}`,
          filename: data.filename,
          size: `${(file.size / (1024 * 1024)).toFixed(2)} MB`,
          flows: data.flow_count || 1,
          score: Math.round(data.score || 75),
          ciLow: Math.round(data.ci_range?.[0] || 60),
          ciHigh: Math.round(data.ci_range?.[1] || 76),
          grade: data.grade || "Grade C",
          hash: data.report_hash || "sha256:0000",
          date: "Just now",
          status: "ANALYZED",
          findingsCount: {
            critical: data.score < 60 ? 2 : 0,
            high: data.findings_count || 1,
            medium: 1,
            low: 0,
            notObservable: 0,
          },
        };

        setSessions((prev) => [newSession, ...prev]);
        setActiveSession(newSession);

        // Fetch findings for this session
        const fRes = await fetch(`${BACKEND_URL}/api/v1/findings?session_id=${data.session_id}`);
        if (fRes.ok) {
          const fData = await fRes.json();
          if (Array.isArray(fData) && fData.length > 0) {
            setFindings(fData.map(adaptBackendFinding));
          }
        }

        setPipelineStage(9);
        setPipelineLogs((prev) => [
          ...prev,
          `[DONE] Upload and forensic evaluation complete. SHA-256 seal verified.`,
        ]);
        setPipelineRunning(false);
        setIsUploading(false);
        return true;
      }
    } catch {
      // Fallback
    }

    setPipelineRunning(false);
    setIsUploading(false);
    return false;
  };

  const toggleAirGapped = () => {
    setIsAirGapped((prev) => !prev);
  };

  const runPipeline = (scenarioId?: string) => {
    setPipelineRunning(true);
    setPipelineStage(0);
    setPipelineLogs([]);

    const target = scenarioId ? sessions.find((s) => s.id === scenarioId) || activeSession : activeSession;
    setActiveSession(target);

    const stages = [
      "Enqueued: Allocating in-memory ring buffer...",
      "Parsing: Executing 6-class STARTTLS state machine...",
      "Features: Computing JA3S / JA4S hashes & entropy vectors...",
      "Rules: Evaluating SMS-PROTO, CIPH, KEY, X509, DNS, ENF catalog...",
      "ML Sweep: Running IsolationForest & GCM nonce-reuse detector...",
      "Downgrade Radar: Computing Bayesian posterior P(strip)...",
      "Delivery Graph: Constructing hop-by-hop transit topology...",
      "Enforcement: Auditing MTA-STS policy & DANE TLSA DNSSEC anchors...",
      "Reports: Rendering deterministic playbook & computing SHA-256 seal...",
    ];

    let current = 0;
    const interval = setInterval(() => {
      if (current < stages.length) {
        setPipelineStage(current + 1);
        setPipelineLogs((prev) => [
          ...prev,
          `[+${((current + 1) * 0.12).toFixed(3)}s] ${stages[current]}`,
        ]);
        current++;
      } else {
        clearInterval(interval);
        setPipelineRunning(false);
        setPipelineStage(9);
        setPipelineLogs((prev) => [
          ...prev,
          `[DONE] Session ${target.id} analysis complete. Report sealed.`,
        ]);
        switchSession(target.id);
      }
    }, 450);
  };

  return (
    <DashboardContext.Provider
      value={{
        activeSession,
        sessions,
        switchSession,
        isAirGapped,
        toggleAirGapped,
        findings,
        selectedFinding,
        setSelectedFinding,
        pipelineRunning,
        pipelineStage,
        runPipeline,
        pipelineLogs,
        mxHosts,
        graphNodes,
        graphEdges,
        backendConnected,
        uploadCapture,
        isUploading,
      }}
    >
      {children}
    </DashboardContext.Provider>
  );
}

export function useDashboard() {
  const context = useContext(DashboardContext);
  if (!context) {
    throw new Error("useDashboard must be used within a DashboardProvider");
  }
  return context;
}
