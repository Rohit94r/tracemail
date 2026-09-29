"use client";

import React from "react";
import Image from "next/image";
import { motion } from "framer-motion";
import { Button } from "./Button";

export function CTASection() {
  return (
    <section className="px-6 py-14 md:py-26">
      <div className="relative mx-auto max-w-7xl overflow-hidden rounded-[32px]">
        {/* Background images */}
        <Image
          src="/blogs-cta-bg.png"
          alt=""
          fill
          className="pointer-events-none absolute inset-0 z-0 object-cover"
        />
        <div className="pointer-events-none absolute inset-y-0 left-1/2 z-0 w-full max-w-3xl -translate-x-1/2">
          <Image
            src="/blogs-cta-lines-bg.png"
            alt=""
            fill
            className="object-contain object-top"
          />
        </div>

        <div className="relative z-10 grid grid-cols-12 items-center gap-6 px-8 py-12 md:px-12 md:py-20">
          {/* Left Animated Cards */}
          <div className="hidden flex-col gap-6 md:col-span-3 md:flex">
            <motion.div
              initial={{ x: -320, opacity: 0, rotate: 6 }}
              whileInView={{ x: -40, opacity: 1, rotate: 3 }}
              viewport={{ once: true, margin: "-100px" }}
              transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
              className="rounded-2xl border border-slate-800 bg-[#0F1420]/95 p-4 text-white shadow-2xl backdrop-blur-md"
            >
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                <span className="text-[10px] font-bold text-emerald-400 font-mono tracking-wider">
                  HANDSHAKE VERIFIED
                </span>
                <span className="rounded bg-emerald-500/20 text-emerald-300 text-[9px] px-1.5 py-0.5 font-bold">
                  TLS 1.3
                </span>
              </div>
              <div className="mt-2.5 space-y-1 text-xs">
                <p className="font-semibold text-slate-200">X25519 · AES_256_GCM</p>
                <p className="text-[11px] text-slate-400 font-mono">DigiCert Global Root G2</p>
                <div className="flex items-center gap-1.5 text-[10px] text-emerald-400 pt-1">
                  <span>✓ Strict Sealing Verified</span>
                </div>
              </div>
            </motion.div>

            <motion.div
              initial={{ x: -320, opacity: 0, rotate: -6 }}
              whileInView={{ x: -40, opacity: 1, rotate: -3 }}
              viewport={{ once: true, margin: "-100px" }}
              transition={{
                duration: 0.85,
                delay: 0.05,
                ease: [0.22, 1, 0.36, 1],
              }}
              className="rounded-2xl border border-red-500/30 bg-[#1A0F14]/95 p-4 text-white shadow-2xl backdrop-blur-md"
            >
              <div className="flex items-center justify-between border-b border-red-500/20 pb-2">
                <span className="text-[10px] font-bold text-red-400 font-mono tracking-wider">
                  DOWNGRADE RADAR
                </span>
                <span className="rounded bg-red-500/20 text-red-300 text-[9px] px-1.5 py-0.5 font-bold animate-pulse">
                  CRITICAL
                </span>
              </div>
              <div className="mt-2.5 space-y-1 text-xs">
                <p className="font-semibold text-red-200">STARTTLS Stripping Detected</p>
                <p className="text-[11px] text-slate-400 font-mono">Packet #1,429 [Offset 0x04F2]</p>
                <div className="flex items-center gap-1.5 text-[10px] text-amber-400 pt-1">
                  <span>⚠ MTA-STS Enforce Violated</span>
                </div>
              </div>
            </motion.div>
          </div>

          {/* Central CTA Content */}
          <div className="col-span-12 flex flex-col items-center text-center md:col-span-6">
            <span className="inline-flex items-center gap-2 rounded-pill bg-primary-soft px-4 py-1.5 text-xs font-bold uppercase tracking-[0.14em] text-primary">
              <svg
                aria-hidden="true"
                className="lucide lucide-sparkles h-3.5 w-3.5"
                fill="none"
                height="24"
                stroke="currentColor"
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2.5"
                viewBox="0 0 24 24"
                width="24"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path d="M11.017 2.814a1 1 0 0 1 1.966 0l1.051 5.558a2 2 0 0 0 1.594 1.594l5.558 1.051a1 1 0 0 1 0 1.966l-5.558 1.051a2 2 0 0 0-1.594 1.594l-1.051 5.558a1 1 0 0 1-1.966 0l-1.051-5.558a2 2 0 0 0-1.594-1.594l-5.558-1.051a1 1 0 0 1 0-1.966l5.558-1.051a2 2 0 0 0 1.594-1.594z" />
                <path d="M20 2v4" />
                <path d="M22 4h-4" />
                <circle cx="4" cy="20" r="2" />
              </svg>
              Get Started
            </span>

            <h2 className="mt-6 text-[36px] font-semibold leading-[1.1] tracking-[-0.03em] text-heading md:text-5xl">
              Ready to Audit Your Email
              <br />
              <span className="text-primary">Cryptographic Posture?</span>
            </h2>

            <p className="mt-4 max-w-md text-base text-body">
              Drop in a PCAP capture or deploy a passive tap to uncover STARTTLS downgrades, invalid certificates, and weak ciphers across your entire mail path.
            </p>

            <div className="mt-8 flex justify-center">
              <Button href="/dashboard" size="lg">
                Launch Raven Platform
              </Button>
            </div>
          </div>

          {/* Right Animated Card */}
          <motion.div
            initial={{ x: 320, opacity: 0, rotate: 6 }}
            whileInView={{ x: 40, opacity: 1, rotate: -2 }}
            viewport={{ once: true, margin: "-100px" }}
            transition={{ duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
            className="hidden md:col-span-3 md:block"
          >
            <div className="rounded-2xl border border-slate-800 bg-[#0F1420]/95 p-5 text-white shadow-2xl backdrop-blur-md">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <span className="text-xs font-bold text-slate-200">EVIDENCE MANIFEST</span>
                <span className="rounded bg-primary/20 text-primary text-[10px] px-2 py-0.5 font-bold">
                  AIR-GAPPED
                </span>
              </div>
              <div className="mt-4 space-y-3 text-xs">
                <div>
                  <span className="text-[11px] text-slate-400 block">Posture Verdict</span>
                  <div className="flex items-baseline gap-2 mt-0.5">
                    <span className="text-2xl font-black text-white">78 / 100</span>
                    <span className="text-emerald-400 font-bold">Grade B+</span>
                  </div>
                </div>
                <div className="border-t border-slate-800/60 pt-2 text-[11px] font-mono text-slate-400 space-y-1">
                  <p>FLOWS: 1,429 analyzed</p>
                  <p>EVIDENCE: SHA-256 sealed</p>
                  <p className="text-primary truncate">HASH: 7f39b2e81...9c</p>
                </div>
                <div className="rounded-lg bg-slate-900 border border-slate-800 p-2 text-center text-[11px] text-slate-300 font-semibold">
                  Court-Grade Audit Receipt ✓
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}
