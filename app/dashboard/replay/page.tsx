"use client";

import React, { useState, useEffect } from "react";
import {
  PlaySquare,
  Play,
  Pause,
  RotateCcw,
  SkipForward,
  SkipBack,
  AlertTriangle,
  Download,
  FileCode,
} from "lucide-react";

interface PacketEvent {
  step: number;
  time: string;
  source: string;
  destination: string;
  protocol: string;
  action: string;
  detail: string;
  hex: string;
  ascii: string;
  isCritical?: boolean;
  ruleId?: string;
  why?: string;
}

const REPLAY_EVENTS: PacketEvent[] = [
  {
    step: 1,
    time: "00:00.000",
    source: "198.51.100.10:48210",
    destination: "198.51.100.14:25",
    protocol: "TCP",
    action: "SYN-ACK 3-Way Handshake",
    detail: "Connection established over TCP Port 25 (Standard SMTP transit).",
    hex: "00 1a 4a 12 b4 80 ... [TCP SYN, SEQ=0]",
    ascii: "[TCP 3-Way Handshake Established]",
  },
  {
    step: 2,
    time: "00:00.042",
    source: "198.51.100.14:25",
    destination: "198.51.100.10:48210",
    protocol: "SMTP",
    action: "Service Ready Banner",
    detail: "Server presents: '220 relay-gw.partner.net ESMTP Postfix'",
    hex: "32 32 30 20 72 65 6c 61 79 2d 67 77 2e 70 61 72 74 6e 65 72 2e 6e 65 74",
    ascii: "220 relay-gw.partner.net ESMTP Postfix\r\n",
  },
  {
    step: 3,
    time: "00:00.088",
    source: "198.51.100.10:48210",
    destination: "198.51.100.14:25",
    protocol: "SMTP",
    action: "Client Greeting (EHLO)",
    detail: "Client introduces hostname: 'EHLO mail.corp.net'",
    hex: "45 48 4c 4f 20 6d 61 69 6c 2e 63 6f 72 70 2e 6e 65 74 0d 0a",
    ascii: "EHLO mail.corp.net\r\n",
  },
  {
    step: 4,
    time: "00:00.140",
    source: "Hop 2 (MITM Proxy)",
    destination: "198.51.100.10:48210",
    protocol: "SMTP / MITM",
    action: "CRITICAL: STARTTLS STRIPPED",
    detail: "Server 250 response intercepted. Adversary in the middle strips 250-STARTTLS keyword before forwarding to client.",
    hex: "32 35 30 2d 50 49 50 45 4c 49 4e 45 0d 0a 32 35 30 2d 53 49 5a 45 20 33 35 38 38 30 30 30 0d 0a",
    ascii: "250-PIPELINE\r\n250-SIZE 3588000\r\n [STARTTLS REMOVED]",
    isCritical: true,
    ruleId: "SMS-ENF-002",
    why: "Active downgrade attack suppresses encryption opportunity, tricking sending MTA into sending in unencrypted plaintext.",
  },
  {
    step: 5,
    time: "00:00.210",
    source: "198.51.100.10:48210",
    destination: "198.51.100.14:25",
    protocol: "SMTP",
    action: "Cleartext Fallback: MAIL FROM",
    detail: "Client MTA falls back to unencrypted transmission: 'MAIL FROM:<cfo@corp.net>'",
    hex: "4d 41 49 4c 20 46 52 4f 4d 3a 3c 63 66 6f 40 63 6f 72 70 2e 6e 65 74 3e 0d 0a",
    ascii: "MAIL FROM:<cfo@corp.net>\r\n [CLEARTEXT TRANSMISSION]",
    isCritical: true,
    ruleId: "SMS-ENF-002",
    why: "Confidential credentials and corporate communications exposed in unencrypted transit.",
  },
  {
    step: 6,
    time: "00:00.280",
    source: "198.51.100.14:25",
    destination: "198.51.100.10:48210",
    protocol: "SMTP",
    action: "Recipient Ok: RCPT TO",
    detail: "Server acknowledges: '250 2.1.5 Ok recipient confirmed'",
    hex: "32 35 30 20 32 2e 31 2e 35 20 4f 6b 0d 0a",
    ascii: "250 2.1.5 Ok\r\n",
  },
];

export default function ReplayPage() {
  const [currentStep, setCurrentStep] = useState<number>(4); // Default to the critical moment
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [speed, setSpeed] = useState<number>(1);

  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isPlaying) {
      timer = setInterval(() => {
        setCurrentStep((prev) => {
          if (prev >= REPLAY_EVENTS.length) {
            setIsPlaying(false);
            return prev;
          }
          return prev + 1;
        });
      }, 1500 / speed);
    }
    return () => clearInterval(timer);
  }, [isPlaying, speed]);

  const activeEvent = REPLAY_EVENTS.find((e) => e.step === currentStep) || REPLAY_EVENTS[3];

  return (
    <div className="space-y-8">
      {/* Title & Section Tag */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="inline-flex items-center gap-2 rounded-full bg-primary-soft px-3 py-1 text-xs font-bold uppercase tracking-wider text-primary mb-2">
            <PlaySquare className="h-3.5 w-3.5" />
            Screen 6 · Forensic Incident Replay
          </div>
          <h1 className="text-3xl font-extrabold tracking-tight text-heading">
            Frame-by-Frame Forensic Replay
          </h1>
          <p className="mt-1 text-sm text-body">
            &quot;Watch how it happened, like a video.&quot; Replay the exact packet-level STARTTLS stripping sequence step-by-step.
          </p>
        </div>

        <button
          onClick={() => alert("Rendering session packet stream to WebM video artifact...")}
          className="inline-flex items-center gap-2 rounded-xl bg-slate-900 px-4 py-2.5 text-xs font-bold text-white hover:bg-slate-800 transition-colors shadow-xs"
        >
          <Download className="h-4 w-4" />
          Export WebM Video Artifact
        </button>
      </div>

      {/* Main Forensic Player Card */}
      <div className="rounded-3xl border border-border bg-white p-6 shadow-xs space-y-6">
        {/* Scrubber & Player Controls (FR-38) */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-border/60 pb-5">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setCurrentStep(1)}
              className="rounded-xl border border-border p-2 text-slate-500 hover:bg-slate-100 transition-colors"
              title="Reset to beginning"
            >
              <RotateCcw className="h-4 w-4" />
            </button>
            <button
              onClick={() => setCurrentStep((prev) => Math.max(1, prev - 1))}
              disabled={currentStep <= 1}
              className="rounded-xl border border-border p-2 text-slate-500 hover:bg-slate-100 transition-colors disabled:opacity-40"
              title="Step Backward"
            >
              <SkipBack className="h-4 w-4" />
            </button>
            <button
              onClick={() => setIsPlaying(!isPlaying)}
              className="flex h-11 w-11 items-center justify-center rounded-xl bg-primary text-white shadow-sm hover:bg-primary-hover transition-colors"
              title={isPlaying ? "Pause" : "Play Replay"}
            >
              {isPlaying ? <Pause className="h-5 w-5" /> : <Play className="h-5 w-5 fill-white ml-0.5" />}
            </button>
            <button
              onClick={() => setCurrentStep((prev) => Math.min(REPLAY_EVENTS.length, prev + 1))}
              disabled={currentStep >= REPLAY_EVENTS.length}
              className="rounded-xl border border-border p-2 text-slate-500 hover:bg-slate-100 transition-colors disabled:opacity-40"
              title="Step Forward"
            >
              <SkipForward className="h-4 w-4" />
            </button>

            <span className="font-mono text-xs font-bold text-slate-700 ml-2">
              Frame {currentStep} of {REPLAY_EVENTS.length} · {activeEvent.time}
            </span>
          </div>

          {/* Speed Selector */}
          <div className="flex items-center gap-1 text-xs">
            <span className="text-slate-400 font-semibold mr-1">Speed:</span>
            {[0.5, 1, 2, 5].map((s) => (
              <button
                key={s}
                onClick={() => setSpeed(s)}
                className={`rounded-lg px-2.5 py-1 font-mono font-bold transition-all ${
                  speed === s ? "bg-slate-900 text-white" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
                }`}
              >
                {s}x
              </button>
            ))}
          </div>
        </div>

        {/* Interactive Timeline Stepper */}
        <div className="grid grid-cols-2 gap-2 md:grid-cols-6">
          {REPLAY_EVENTS.map((event) => {
            const isCurrent = event.step === currentStep;
            const isPast = event.step < currentStep;

            return (
              <button
                key={event.step}
                onClick={() => {
                  setCurrentStep(event.step);
                  setIsPlaying(false);
                }}
                className={`flex flex-col items-start rounded-2xl border p-3 text-left transition-all ${
                  isCurrent
                    ? event.isCritical
                      ? "border-red-500 bg-red-50 ring-2 ring-red-400"
                      : "border-primary bg-primary-soft ring-2 ring-primary/30"
                    : event.isCritical
                    ? "border-red-200 bg-red-50/50 hover:bg-red-50"
                    : isPast
                    ? "border-slate-200 bg-slate-50 hover:bg-slate-100"
                    : "border-border/60 bg-surface-soft/40 opacity-50"
                }`}
              >
                <div className="flex items-center justify-between w-full mb-1">
                  <span className="font-mono text-[10px] text-slate-400">#{event.step} · {event.time}</span>
                  {event.isCritical && (
                    <span className="h-2 w-2 rounded-full bg-red-500 animate-ping" />
                  )}
                </div>
                <div className="font-bold text-xs text-heading truncate w-full">
                  {event.action}
                </div>
                <div className="font-mono text-[10px] text-muted truncate w-full mt-0.5">
                  {event.protocol}
                </div>
              </button>
            );
          })}
        </div>

        {/* Active Frame Inspection Window */}
        <div className="grid gap-6 md:grid-cols-2">
          {/* Left: Forensic Narrative */}
          <div className="rounded-2xl border border-border bg-surface-soft p-5 space-y-4">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs font-bold text-primary uppercase">
                FRAME #{activeEvent.step} DETAIL
              </span>
              {activeEvent.isCritical && (
                <span className="rounded-md bg-red-600 px-2 py-0.5 text-[10px] font-extrabold uppercase text-white shadow-xs animate-pulse">
                  CRITICAL INCIDENT
                </span>
              )}
            </div>

            <div>
              <h3 className="text-lg font-bold text-heading">
                {activeEvent.action}
              </h3>
              <p className="text-xs text-slate-700 leading-relaxed mt-2">
                {activeEvent.detail}
              </p>
            </div>

            {activeEvent.isCritical && (
              <div className="rounded-xl border border-red-200 bg-red-50 p-3.5 space-y-1.5">
                <div className="flex items-center gap-1.5 text-xs font-bold text-red-700">
                  <AlertTriangle className="h-4 w-4" />
                  <span>Rule Citation: {activeEvent.ruleId}</span>
                </div>
                <p className="text-xs text-red-800 leading-relaxed">
                  {activeEvent.why}
                </p>
              </div>
            )}

            <div className="grid grid-cols-2 gap-2 text-xs pt-2 border-t border-border/60">
              <div>
                <span className="text-muted block text-[11px]">Source Socket:</span>
                <span className="font-mono font-semibold text-slate-800">{activeEvent.source}</span>
              </div>
              <div>
                <span className="text-muted block text-[11px]">Destination Socket:</span>
                <span className="font-mono font-semibold text-slate-800">{activeEvent.destination}</span>
              </div>
            </div>
          </div>

          {/* Right: Dual Hex / ASCII Wire Stream */}
          <div className="rounded-2xl border border-slate-800 bg-slate-950 p-5 font-mono text-xs text-slate-200 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2 text-[11px] text-slate-400">
              <span className="flex items-center gap-1.5">
                <FileCode className="h-3.5 w-3.5 text-primary" />
                Raw Packet Wire Inspection
              </span>
              <span>Offset: 0x00004F2A</span>
            </div>

            <div>
              <span className="text-[10px] text-slate-500 block uppercase mb-1">
                Hex Byte Stream:
              </span>
              <p className="text-amber-400/90 leading-relaxed break-all select-all">
                {activeEvent.hex}
              </p>
            </div>

            <div className="pt-2 border-t border-slate-800">
              <span className="text-[10px] text-slate-500 block uppercase mb-1">
                Decoded ASCII Protocol Stream:
              </span>
              <p className={activeEvent.isCritical ? "text-red-400 font-bold" : "text-emerald-400"}>
                {activeEvent.ascii}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
