"use client";

import React from "react";
import Image from "next/image";
import { motion } from "framer-motion";
import { Button } from "./Button";
import { RavenDashboardPreview } from "./RavenDashboardPreview";

const fadeUp = {
  initial: { opacity: 0, y: 24 },
  animate: { opacity: 1, y: 0 },
};

export function Hero() {
  return (
    <section className="relative overflow-hidden pt-36 md:pt-44" id="overview">
      {/* Background Grids */}
      <div className="pointer-events-none absolute inset-x-0 top-23 z-0 flex justify-center">
        <div className="relative h-[1100px] w-full max-w-[1400px]">
          <Image
            src="/bg-lines.png"
            alt=""
            fill
            priority
            className="object-contain object-top"
          />
        </div>
      </div>

      <div className="relative z-10 mx-auto max-w-7xl px-6">
        <motion.div
          {...fadeUp}
          transition={{ duration: 0.5 }}
          className="flex justify-center"
        >
          <span className="inline-flex items-center gap-3 rounded-pill border border-border bg-white py-1.5 pl-1.5 pr-5 text-sm shadow-[0_2px_8px_-2px_rgba(12,12,12,0.06)]">
            <span className="rounded-pill bg-primary-soft px-3 py-1 text-xs font-semibold text-primary">
              Passive Defense
            </span>
            <span className="font-medium text-heading">
              Zero Active Probing · 100% Observational
            </span>
          </span>
        </motion.div>

        <motion.h1
          {...fadeUp}
          transition={{ duration: 0.55, delay: 0.05 }}
          className="mx-auto mt-8 max-w-5xl text-center text-[44px] font-semibold leading-[1.1] tracking-[-0.03em] text-heading md:text-7xl lg:text-[68px]"
        >
          <span className="text-primary"> Raven </span>
          - Audit Your Email Encryption Without Sending a Single Packet
        </motion.h1>

        <motion.p
          {...fadeUp}
          transition={{ duration: 0.55, delay: 0.12 }}
          className="mx-auto mt-7 max-w-2xl text-center text-lg text-body"
        >
          Most of the world&apos;s email still travels like an open letter. Raven passively observes your mail traffic, verifies whether every hop was cryptographically sealed, and produces a confidence-bounded posture score with court-grade forensic receipts.
        </motion.p>

        <motion.div
          {...fadeUp}
          transition={{ duration: 0.55, delay: 0.2 }}
          className="mt-[43px] flex flex-wrap items-center justify-center gap-4"
        >
          <Button href="/dashboard" size="lg">
            Launch Console & Ingest PCAP
          </Button>
          <a
            href="#capabilities"
            className="inline-flex items-center rounded-pill border border-border bg-white px-7 py-3 text-base font-medium text-heading shadow-sm transition-all hover:border-primary hover:text-primary"
          >
            Explore Capabilities
          </a>
        </motion.div>
      </div>

      {/* Hero Dashboard Preview Window */}
      <div className="relative mt-16 md:mt-24">
        <div className="pointer-events-none absolute inset-x-6 -top-24 bottom-0 z-0 select-none md:-top-40">
          <Image
            src="/hero-bg.webp"
            alt=""
            fill
            className="object-fill"
          />
        </div>

        <div className="relative z-10 mx-4 md:mx-auto max-w-6xl">
          <motion.div
            initial={{ opacity: 0, y: 60 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{
              duration: 0.8,
              delay: 0.35,
              ease: [0.22, 1, 0.36, 1],
            }}
            className="rounded-[20px] md:rounded-[28px] border border-white/50 bg-white/30 p-2 md:p-5 shadow-[0_40px_100px_-30px_rgba(12,12,12,0.15)] backdrop-blur-md"
          >
            <RavenDashboardPreview />
          </motion.div>
        </div>
      </div>
    </section>
  );
}
