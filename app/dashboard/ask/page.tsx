"use client";

import React, { useState } from "react";
import Link from "next/link";
import {
  Sparkles,
  Send,
  ExternalLink,
  Bot,
  User,
} from "lucide-react";
import { useDashboard } from "@/components/dashboard/DashboardContext";

interface Citation {
  span_id: string;
  source: string;
  data_source: "observed" | "derived" | "demo_fixture";
  rule_id: string | null;
  packet_no: number | null;
}

interface ChatMessage {
  sender: "user" | "raven";
  text: string;
  citations?: Citation[];
  isRefusal?: boolean;
}

import { EmptyState } from "@/components/ui/EmptyState";

/**
 * Suggestions must be answerable from the retrieval corpus: RFC/NIST
 * requirement text, the scoring rubric, and this capture's findings. A prompt
 * outside that set can only be refused, which looks like a broken product.
 */
const SAMPLE_PROMPTS = [
  "What does SMS-ENF-002 mean and what triggers it?",
  "What is the minimum recommended RSA key size?",
  "Why is STARTTLS stripping dangerous?",
  "How is the posture index calculated?",
  "What certificate problem was found in this capture?",
  "What does RFC 8461 require for MTA-STS?",
];

export default function AskPage() {
  const { activeSession, loadSampleCapture } = useDashboard();
  const [input, setInput] = useState("");
  const [isAsking, setIsAsking] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      sender: "raven",
      text: "I am the SecureMailScope forensic assistant. I answer strictly from this capture\u2019s findings, published RFC/NIST criteria, and the scoring rubric. Every sentence I write is checked against the evidence it cites \u2014 if I cannot ground a claim, I refuse instead of guessing. Ingest a capture to begin.",
    },
  ]);

  if (!activeSession) {
    return (
      <EmptyState
        icon={<Sparkles className="h-6 w-6 text-blue-600" />}
        title="No Capture Loaded for Forensic Assistant"
        description="Ingest a packet capture to query the forensic assistant. Every answer is grounded and cited; questions the evidence cannot answer are refused."
        primaryAction={{
          label: "Go to Ingestion",
          href: "/dashboard",
        }}
        secondaryAction={{
          label: "Try Sample Capture (1-Click)",
          onClick: () => loadSampleCapture("stripped"),
        }}
        note="Refuses out-of-scope and ungroundable queries"
      />
    );
  }

  const handleSend = async (text: string) => {
    if (!text.trim()) return;

    const userMsg: ChatMessage = { sender: "user", text };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setIsAsking(true);

    const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001";
    let data: {
      answer: string | null;
      citations?: Citation[];
      refused: boolean;
      refusal_reason?: string | null;
    };

    try {
      const res = await fetch(`${apiUrl}/api/v1/ask`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: text, session_id: activeSession.id }),
      });
      if (!res.ok) throw new Error(`assistant returned ${res.status}`);
      data = await res.json();
    } catch (err) {
      // The backend is the only source of evidence. If it is unreachable we
      // report that plainly rather than composing an answer locally: a
      // fabricated packet number or score is worse than no answer, because an
      // analyst cannot tell it apart from a real one.
      setMessages((prev) => [
        ...prev,
        {
          sender: "raven",
          text: `UNAVAILABLE: the analysis backend could not be reached (${
            err instanceof Error ? err.message : "network error"
          }). No answer was generated, because this assistant only reports evidence it can cite. Check that the API is running at ${apiUrl}.`,
          isRefusal: true,
        },
      ]);
      setIsAsking(false);
      return;
    }

    setMessages((prev) => [
      ...prev,
      {
        sender: "raven",
        // A refusal has answer=null; the reason is the useful part.
        text: data.answer ?? data.refusal_reason ?? "No answer produced.",
        citations: data.citations ?? [],
        isRefusal: data.refused,
      },
    ]);
    setIsAsking(false);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="inline-flex items-center gap-1.5 rounded-md bg-slate-100 px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wider text-slate-700 mb-2">
          <Sparkles className="h-3.5 w-3.5 text-slate-600" />
          RAG Forensic Assistant
        </div>
        <h1 className="text-3xl font-extrabold tracking-tight text-heading">
          Grounded Forensic AI (Ask Raven)
        </h1>
        <p className="mt-1 text-sm text-body">
          Natural language Q&A strictly grounded in the capture&apos;s observed packets, feature tensors, and RFC rules. Zero cloud egress.
        </p>
      </div>

      {/* Main Chat Interface */}
      <div className="flex flex-col h-[640px] rounded-3xl border border-border bg-white shadow-xs overflow-hidden">
        {/* Messages scroll area */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4 bg-surface-soft/40">
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`flex gap-3 max-w-3xl ${
                msg.sender === "user" ? "ml-auto flex-row-reverse" : ""
              }`}
            >
              <div
                className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-xl font-bold text-xs ${
                  msg.sender === "user"
                    ? "bg-primary text-white"
                    : "bg-slate-900 text-white"
                }`}
              >
                {msg.sender === "user" ? <User className="h-4 w-4" /> : <Bot className="h-4 w-4" />}
              </div>

              <div
                className={`rounded-2xl p-4 text-xs leading-relaxed ${
                  msg.sender === "user"
                    ? "bg-primary text-white"
                    : msg.isRefusal
                    ? "bg-amber-50 border border-amber-300 text-amber-900"
                    : "bg-white border border-border text-slate-800 shadow-xs"
                }`}
              >
                <p>{msg.text}</p>

                {/* Evidence Citations */}
                {msg.citations && msg.citations.length > 0 && (
                  <div className="mt-3 pt-3 border-t border-border/60">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 block mb-1.5">
                      Grounded Forensic Citations:
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {msg.citations.map((cite) =>
                        cite.rule_id ? (
                          <Link
                            key={cite.span_id}
                            href={`/dashboard/findings?id=${cite.rule_id}`}
                            className="inline-flex items-center gap-1 rounded-md bg-primary-soft px-2 py-1 font-mono text-[10px] font-bold text-primary hover:bg-primary hover:text-white transition-colors"
                          >
                            <span>{cite.rule_id}</span>
                            {cite.packet_no != null && (
                              <span className="font-sans font-normal opacity-70">
                                pkt {cite.packet_no}
                              </span>
                            )}
                            <ExternalLink className="h-2.5 w-2.5" />
                          </Link>
                        ) : (
                          // Reference spans (RFC, rubric) have no finding to
                          // deep-link to, so they render as plain provenance.
                          <span
                            key={cite.span_id}
                            title={cite.source}
                            className="inline-flex items-center gap-1 rounded-md bg-slate-100 px-2 py-1 font-mono text-[10px] font-bold text-slate-600"
                          >
                            <span>{cite.span_id}</span>
                            <span className="font-sans font-normal opacity-60">
                              {cite.data_source}
                            </span>
                          </span>
                        )
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Suggested Prompt Chips */}
        <div className="border-t border-border bg-white px-6 py-2.5 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-400 font-semibold text-[11px]">Suggestions:</span>
          {SAMPLE_PROMPTS.map((p) => (
            <button
              key={p}
              onClick={() => handleSend(p)}
              className="rounded-lg border border-border bg-surface-soft px-2.5 py-1 text-[11px] text-slate-600 hover:border-slate-300 hover:bg-slate-100 transition-colors"
            >
              {p}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <div className="border-t border-border bg-white p-4">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSend(input);
            }}
            className="flex gap-2"
          >
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Ask about cryptographic findings, flow proofs, or RFC compliance..."
              className="flex-1 rounded-xl border border-border bg-surface-soft px-4 py-2.5 text-xs font-medium text-slate-900 focus:outline-none focus:ring-2 focus:ring-primary/20"
            />
            <button
              type="submit"
              disabled={!input.trim() || isAsking}
              className="inline-flex items-center gap-1.5 rounded-xl bg-primary px-4 py-2.5 text-xs font-bold text-white hover:bg-primary-hover transition-colors disabled:opacity-40"
            >
              <Send className={`h-3.5 w-3.5 ${isAsking ? "animate-spin" : ""}`} />
              <span>{isAsking ? "Analyzing..." : "Ask"}</span>
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
