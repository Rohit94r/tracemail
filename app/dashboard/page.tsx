"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  UploadCloud,
  AlertTriangle,
  Play,
  CheckCircle2,
  FolderOpen,
  ArrowRight,
  RefreshCw,
  Cpu,
  Layers,
  Clock,
} from "lucide-react";
import { useDashboard } from "@/components/dashboard/DashboardContext";

export default function IngestPage() {
  const {
    activeSession,
    sessions,
    switchSession,
    pipelineRunning,
    pipelineStage,
    runPipeline,
    pipelineLogs,
    uploadCapture,
    isUploading,
  } = useDashboard();

  const [folderPath, setFolderPath] = useState("/var/log/mailcap/live_spool/");
  const [folderWatch, setFolderWatch] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [uploadedFileName, setUploadedFileName] = useState<string | null>(null);

  const pipelineStages = [
    { name: "Enqueued", desc: "Ring buffer allocation" },
    { name: "Parsing", desc: "6-class STARTTLS state machine" },
    { name: "Features", desc: "25-dim cryptographic tensors" },
    { name: "Rules", desc: "RFC catalog evaluation" },
    { name: "ML Sweep", desc: "Anomaly detection & entropy" },
    { name: "Downgrade Radar", desc: "Bayesian P(strip) posterior" },
    { name: "Delivery Graph", desc: "Hop topology builder" },
    { name: "Enforcement", desc: "MTA-STS & DANE TLSA check" },
    { name: "Reports", desc: "SHA-256 seal & playbook" },
  ];

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      setUploadedFileName(file.name);
      await uploadCapture(file);
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Overview Banner */}
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between border-b border-slate-200/80 pb-5">
        <div>
          <div className="inline-flex items-center gap-1.5 rounded-md bg-slate-100 px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider text-slate-700 mb-1.5">
            <Cpu className="h-3 w-3 text-slate-500" />
            Ingest & Evaluation Pipeline
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-slate-900">
            Packet Capture Ingestion
          </h1>
          <p className="mt-0.5 text-xs text-slate-600">
            Drop raw <code className="font-mono bg-slate-100 text-slate-800 px-1 py-0.5 rounded text-[11px]">.pcap</code> / <code className="font-mono bg-slate-100 text-slate-800 px-1 py-0.5 rounded text-[11px]">.pcapng</code> captures to execute the 9-stage deterministic forensic pipeline.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            onClick={() => runPipeline()}
            disabled={pipelineRunning}
            className="inline-flex items-center gap-2 rounded-lg bg-slate-900 px-4 py-2 text-xs font-semibold text-white shadow-xs hover:bg-slate-800 transition-all disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5 fill-white" />
            {pipelineRunning ? "Analyzing Capture..." : "Run Pipeline Sweep"}
          </button>
        </div>
      </div>

      {/* Main Ingestion Grid: Dropzone + Preset Scenarios */}
      <div className="grid gap-5 lg:grid-cols-3">
        {/* Left 2 Cols: Dropzone & Folder Mode */}
        <div className="lg:col-span-2 space-y-5">
          {/* Dropzone */}
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            className={`relative flex flex-col items-center justify-center rounded-2xl border-2 border-dashed p-8 text-center transition-all bg-white ${
              dragOver
                ? "border-blue-500 bg-blue-50/20"
                : "border-slate-200 hover:border-slate-400"
            }`}
          >
            <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-slate-100 text-slate-700 mb-3 shadow-xs">
              <UploadCloud className="h-6 w-6" />
            </div>

            <h3 className="text-sm font-bold text-slate-900">
              {uploadedFileName
                ? `Selected: ${uploadedFileName}`
                : "Drag & drop packet capture file here"}
            </h3>
            <p className="mt-1 max-w-sm text-xs text-slate-500">
              Supports <strong className="text-slate-700">.pcap</strong> and{" "}
              <strong className="text-slate-700">.pcapng</strong>. 100% passive memory parsing with zero active probe transmission.
            </p>

            <div className="mt-5 flex flex-wrap items-center justify-center gap-2.5">
              <label className="cursor-pointer rounded-lg bg-slate-900 px-3.5 py-2 text-xs font-semibold text-white hover:bg-slate-800 transition-colors shadow-xs">
                {isUploading ? "Ingesting PCAP..." : "Browse Local Files"}
                <input
                  type="file"
                  accept=".pcap,.pcapng,.cap"
                  disabled={isUploading}
                  className="hidden"
                  onChange={async (e) => {
                    if (e.target.files && e.target.files[0]) {
                      const file = e.target.files[0];
                      setUploadedFileName(file.name);
                      await uploadCapture(file);
                    }
                  }}
                />
              </label>
              <button
                type="button"
                onClick={() => {
                  switchSession("scenario-stripped");
                  runPipeline("scenario-stripped");
                }}
                className="rounded-lg border border-slate-200 bg-slate-50 px-3.5 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-100 transition-colors"
              >
                Load Sample Stripped PCAP
              </button>
            </div>
          </div>

          {/* Folder Mode */}
          <div className="rounded-xl border border-slate-200 bg-white p-4">
            <div className="flex items-center justify-between mb-2.5">
              <div className="flex items-center gap-2">
                <FolderOpen className="h-4 w-4 text-slate-500" />
                <span className="text-xs font-bold text-slate-800">
                  Directory Spool Watcher (Folder Mode)
                </span>
              </div>
              <label className="flex items-center gap-1.5 text-xs text-slate-600 cursor-pointer">
                <input
                  type="checkbox"
                  checked={folderWatch}
                  onChange={(e) => setFolderWatch(e.target.checked)}
                  className="h-3.5 w-3.5 rounded border-slate-300 text-blue-600 focus:ring-blue-500"
                />
                Watch Mode
              </label>
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                value={folderPath}
                onChange={(e) => setFolderPath(e.target.value)}
                className="flex-1 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 font-mono text-xs text-slate-800 focus:outline-none focus:border-slate-400"
                placeholder="/path/to/pcap/directory"
              />
              <button
                onClick={() => runPipeline()}
                className="rounded-lg bg-slate-100 px-3.5 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-200 transition-colors"
              >
                Ingest
              </button>
            </div>
          </div>
        </div>

        {/* Right 1 Col: Quick Test Scenarios */}
        <div className="rounded-2xl border border-slate-200 bg-white p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
              <Layers className="h-4 w-4 text-slate-500" />
              Corpus Reference Scenarios
            </h3>
            <span className="text-[10px] font-mono text-slate-500">{sessions.length} Available</span>
          </div>
          <p className="text-[11px] text-slate-500 leading-relaxed">
            Select a verified capture to run rule and posture evaluation:
          </p>

          <div className="space-y-1.5">
            {sessions.map((scenario) => {
              const isActive = scenario.id === activeSession.id;
              return (
                <div
                  key={scenario.id}
                  onClick={() => switchSession(scenario.id)}
                  className={`cursor-pointer rounded-xl border p-3 transition-all ${
                    isActive
                      ? "border-slate-800 bg-slate-50 shadow-xs"
                      : "border-slate-100 hover:border-slate-300 hover:bg-slate-50/50"
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="text-xs font-bold text-slate-900">
                        {scenario.name}
                      </div>
                      <div className="mt-0.5 font-mono text-[10px] text-slate-500">
                        {scenario.filename}
                      </div>
                    </div>
                    <span
                      className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                        scenario.score >= 80
                          ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                          : scenario.score >= 60
                          ? "bg-amber-50 text-amber-700 border border-amber-200"
                          : "bg-red-50 text-red-700 border border-red-200"
                      }`}
                    >
                      {scenario.grade}
                    </span>
                  </div>

                  <div className="mt-2 flex items-center justify-between pt-1.5 border-t border-slate-100 text-[10px]">
                    <span className="font-mono text-slate-500">
                      {scenario.flows.toLocaleString()} flow(s)
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        switchSession(scenario.id);
                        runPipeline(scenario.id);
                      }}
                      className="font-semibold text-slate-900 hover:text-blue-600 flex items-center gap-1"
                    >
                      Evaluate <ArrowRight className="h-3 w-3" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Pipeline Progress Stages */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-xs">
        <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between mb-4">
          <div>
            <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
              <RefreshCw
                className={`h-4 w-4 ${pipelineRunning ? "animate-spin text-blue-600" : "text-emerald-500"}`}
              />
              Deterministic Ingestion Pipeline Status
            </h3>
            <p className="text-xs text-slate-500">
              Sequential 9-stage evaluation with frozen package priors and verifiable state transitions.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="font-mono text-xs font-semibold text-slate-700">
              {pipelineRunning
                ? `Stage ${pipelineStage}/9: In Progress`
                : "Pipeline Complete (100%)"}
            </span>
          </div>
        </div>

        {/* 9 Stage Chips */}
        <div className="grid grid-cols-3 gap-2 md:grid-cols-9">
          {pipelineStages.map((stage, idx) => {
            const stageNum = idx + 1;
            const isCompleted = pipelineStage >= stageNum;
            const isCurrent = pipelineStage === stageNum && pipelineRunning;

            return (
              <div
                key={idx}
                className={`rounded-xl border p-2.5 text-center transition-all ${
                  isCurrent
                    ? "border-blue-600 bg-blue-50 text-blue-900"
                    : isCompleted
                    ? "border-emerald-200 bg-emerald-50/60"
                    : "border-slate-100 bg-slate-50/50 opacity-60"
                }`}
              >
                <div className="flex items-center justify-center mb-1">
                  {isCurrent ? (
                    <RefreshCw className="h-3.5 w-3.5 animate-spin text-blue-600" />
                  ) : isCompleted ? (
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" />
                  ) : (
                    <div className="h-3.5 w-3.5 rounded-full border border-slate-300 text-[9px] font-mono flex items-center justify-center text-slate-400">
                      {stageNum}
                    </div>
                  )}
                </div>
                <div className="text-[11px] font-bold text-slate-900 truncate">
                  {stage.name}
                </div>
                <div className="text-[9px] text-slate-500 truncate mt-0.5">
                  {stage.desc}
                </div>
              </div>
            );
          })}
        </div>

        {/* Pipeline Log Stream Output */}
        <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950 p-3.5 font-mono text-xs text-slate-300">
          <div className="flex items-center justify-between border-b border-slate-800 pb-1.5 mb-2 text-[10px] text-slate-500">
            <span>PIPELINE EXECUTION TELEMETRY STREAM</span>
            <span>AIR-GAPPED · ZERO EGRESS</span>
          </div>
          <div className="space-y-1 max-h-32 overflow-y-auto">
            {pipelineLogs.map((log, i) => (
              <div key={i} className="text-slate-300 text-[11px]">
                <span className="text-emerald-400 font-semibold">{log.slice(0, 11)}</span>
                <span className="text-slate-300">{log.slice(11)}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Done Session Result & One-Click Handoff */}
      <div className="rounded-2xl border border-slate-200 bg-slate-50 p-5 flex flex-col md:flex-row items-center justify-between gap-4 shadow-xs">
        <div className="space-y-0.5">
          <div className="flex items-center gap-2">
            <span className="flex h-2 w-2 rounded-full bg-emerald-500" />
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-700">
              Evaluation Active · {activeSession.id}
            </span>
          </div>
          <h4 className="text-base font-bold text-slate-900">
            {activeSession.flows.toLocaleString()} Flow(s) Analyzed · Verdict:{" "}
            <span className="text-slate-900">{activeSession.grade}</span> ({activeSession.score}/100)
          </h4>
          <p className="text-[11px] text-slate-500 font-mono">
            Report SHA-256: {activeSession.hash.slice(0, 36)}...
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <Link
            href="/dashboard/findings"
            className="inline-flex items-center gap-1.5 rounded-lg bg-slate-900 px-4 py-2.5 text-xs font-semibold text-white hover:bg-slate-800 transition-colors"
          >
            <span>View Findings</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </Link>
          <Link
            href="/dashboard/posture"
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-4 py-2.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition-colors"
          >
            <span>Posture Breakdown</span>
          </Link>
        </div>
      </div>

      {/* Warnings & Session History Table */}
      <div className="grid gap-5 lg:grid-cols-3">
        {/* Non-blocking warnings */}
        <div className="rounded-2xl border border-slate-200 bg-white p-5 space-y-3">
          <div className="flex items-center gap-2 text-slate-800 font-bold text-xs uppercase tracking-wider">
            <AlertTriangle className="h-4 w-4 text-amber-500" />
            Telemetry & Flow Notes
          </div>
          <p className="text-xs text-slate-500 leading-relaxed">
            Passive verification status for current capture session:
          </p>

          <div className="space-y-2 text-xs">
            <div className="rounded-lg border border-slate-100 bg-slate-50 p-2.5 text-slate-700">
              <strong className="text-slate-800 block text-[11px]">TCP Reassembly Clean</strong>
              <span className="text-[11px] text-slate-500">Flow sequences normalized before deterministic rule evaluation.</span>
            </div>
            <div className="rounded-lg border border-slate-100 bg-slate-50 p-2.5 text-slate-700">
              <strong className="text-slate-800 block text-[11px]">Zero Network Egress</strong>
              <span className="text-[11px] text-slate-500">No active probes sent to peer MTAs or external DNS resolvers.</span>
            </div>
          </div>
        </div>

        {/* Past Sessions History Table */}
        <div className="lg:col-span-2 rounded-2xl border border-slate-200 bg-white p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
              <Clock className="h-4 w-4 text-slate-500" />
              Ingested Capture Sessions (MongoDB Atlas)
            </h3>
            <span className="text-xs text-slate-500 font-mono">{sessions.length} Recorded</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-slate-100 text-slate-500 font-semibold uppercase text-[10px]">
                  <th className="pb-2.5">Session ID</th>
                  <th className="pb-2.5">File</th>
                  <th className="pb-2.5">Flows</th>
                  <th className="pb-2.5">Score & CI</th>
                  <th className="pb-2.5">Grade</th>
                  <th className="pb-2.5 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {sessions.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-50/80 transition-colors">
                    <td className="py-2.5 font-mono font-medium text-slate-800">
                      {s.id}
                    </td>
                    <td className="py-2.5 text-slate-600">
                      {s.filename}
                    </td>
                    <td className="py-2.5 font-mono text-slate-500">
                      {s.flows.toLocaleString()}
                    </td>
                    <td className="py-2.5 font-mono font-medium">
                      <span className={s.score >= 80 ? "text-emerald-700 font-bold" : s.score >= 60 ? "text-amber-700 font-bold" : "text-red-700 font-bold"}>
                        {s.score}
                      </span>{" "}
                      <span className="text-slate-400 font-normal">[{s.ciLow}–{s.ciHigh}]</span>
                    </td>
                    <td className="py-2.5">
                      <span className={`rounded px-1.5 py-0.5 text-[10px] font-bold ${
                        s.score >= 80 ? "bg-emerald-50 text-emerald-700" : s.score >= 60 ? "bg-amber-50 text-amber-700" : "bg-red-50 text-red-700"
                      }`}>
                        {s.grade}
                      </span>
                    </td>
                    <td className="py-2.5 text-right">
                      <button
                        onClick={() => {
                          switchSession(s.id);
                        }}
                        className="font-semibold text-slate-800 hover:text-blue-600"
                      >
                        Inspect →
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
