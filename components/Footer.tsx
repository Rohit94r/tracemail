import React from "react";
import Link from "next/link";
import Image from "next/image";
import { RavenWordmark } from "./RavenWordmark";

export function Footer() {
  return (
    <footer className="relative overflow-hidden bg-heading text-white">
      <div className="mx-auto max-w-7xl px-6 pt-20 pb-10">
        <div className="grid grid-cols-1 gap-12 lg:grid-cols-12">
          {/* Brand info */}
          <div className="lg:col-span-4">
            <Link className="inline-flex items-center" href="/">
              <Image
                src="/raven_logo.svg"
                alt="Raven by SecureMailScope"
                width={160}
                height={40}
                className="h-10 w-auto brightness-0 invert"
              />
            </Link>
            <p className="mt-7 max-w-[320px] text-[26px] font-medium leading-[1.2] text-white">
              Raven. Cryptographic certainty for email infrastructure.
            </p>
            <p className="mt-4 text-sm text-white/60">
              100% passive, air-gapped cryptographic posture assessment and downgrade detection from captured SMTP/IMAP/POP3 traffic.
            </p>
          </div>

          {/* Links grid */}
          <div className="grid grid-cols-1 gap-10 sm:grid-cols-2 lg:col-span-8 lg:grid-cols-2 xl:grid-cols-4">
            {/* Column 1: Platform */}
            <div>
              <h4 className="text-xl font-semibold text-white">Platform</h4>
              <ul className="mt-8 space-y-4">
                <li>
                  <Link
                    className="text-base text-white/70 transition-colors hover:text-white"
                    href="/"
                  >
                    Overview
                  </Link>
                </li>
                <li>
                  <a
                    className="text-base text-white/70 transition-colors hover:text-white"
                    href="#problem"
                  >
                    The Problem
                  </a>
                </li>
                <li>
                  <a
                    className="text-base text-white/70 transition-colors hover:text-white"
                    href="#deployment"
                  >
                    Deployment Modes
                  </a>
                </li>
                <li>
                  <a
                    className="text-base text-white/70 transition-colors hover:text-white"
                    href="#faq"
                  >
                    Technical Specs
                  </a>
                </li>
              </ul>
            </div>

            {/* Column 2: Standards & Protocols */}
            <div>
              <h4 className="text-xl font-semibold text-white">Standards</h4>
              <ul className="mt-8 space-y-4">
                <li>
                  <span className="text-base text-white/70">RFC 8461 (MTA-STS)</span>
                </li>
                <li>
                  <span className="text-base text-white/70">RFC 7672 (DANE TLSA)</span>
                </li>
                <li>
                  <span className="text-base text-white/70">RFC 8460 (TLS-RPT)</span>
                </li>
                <li>
                  <span className="text-base text-white/70">NIST SP 800-52r2</span>
                </li>
                <li>
                  <span className="text-base text-white/70">STARTTLS State Machine</span>
                </li>
                <li>
                  <span className="text-base text-white/70">Post-Quantum Cryptography</span>
                </li>
              </ul>
            </div>

            {/* Column 3: Operational Roles */}
            <div>
              <h4 className="text-xl font-semibold text-white">Target Roles</h4>
              <ul className="mt-8 space-y-4">
                <li>
                  <span className="text-base text-white/70">SOC Analysts</span>
                </li>
                <li>
                  <span className="text-base text-white/70">DFIR Examiners</span>
                </li>
                <li>
                  <span className="text-base text-white/70">Mail Administrators</span>
                </li>
                <li>
                  <span className="text-base text-white/70">Sovereign CERT Teams</span>
                </li>
                <li>
                  <span className="text-base text-white/70">Security Auditors</span>
                </li>
                <li>
                  <span className="text-base text-white/70">Threat Hunters</span>
                </li>
              </ul>
            </div>

            {/* Column 4: Architecture */}
            <div>
              <h4 className="text-xl font-semibold text-white">Architecture</h4>
              <ul className="mt-8 space-y-4">
                <li>
                  <span className="text-base text-white/70">Passive PCAP Ingest</span>
                </li>
                <li>
                  <span className="text-base text-white/70">TAP / SPAN Mirror Port</span>
                </li>
                <li>
                  <span className="text-base text-white/70">Confidence Bounds (CI)</span>
                </li>
                <li>
                  <span className="text-base text-white/70">Delivery Graph Mapping</span>
                </li>
                <li>
                  <span className="text-base text-white/70">SHA-256 Signed Evidence</span>
                </li>
                <li>
                  <span className="text-base text-white/70">Air-Gapped Execution</span>
                </li>
              </ul>
            </div>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="mt-20 flex flex-col gap-8 border-t border-white/10 pt-8 md:flex-row md:items-end md:justify-between">
          <div>
            <div className="flex items-center gap-5">
              <span className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/5 px-3 py-1 text-xs font-medium text-white/80">
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                Air-Gapped · Passive · Deterministic
              </span>
            </div>
            <p className="mt-4 text-sm text-white/60">
              Copyright © 2026 Raven by SecureMailScope. Developed for Smart India Hackathon.
            </p>
            <p className="mt-1 text-xs text-white/40">
              Deterministic RFC/NIST cryptographic posture assessment. Zero active probing.
            </p>
          </div>

          <div className="flex items-center gap-8">
            <span className="text-sm text-white/70">RFC Compliant</span>
            <span className="text-sm text-white/70">NIST SP 800-52r2</span>
            <span className="text-sm text-white/70">Offline First</span>
          </div>
        </div>
      </div>

      {/* Giant Typography Wordmark */}
      <div className="pb-6">
        <RavenWordmark />
      </div>
    </footer>
  );
}
