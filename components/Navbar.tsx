"use client";

import React, { useState, useEffect, useRef } from "react";
import Link from "next/link";
import Image from "next/image";
import { Button } from "./Button";

export function Navbar() {
  const [scrolled, setScrolled] = useState(false);
  const [moreOpen, setMoreOpen] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const moreRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 40);
    };
    window.addEventListener("scroll", handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (moreRef.current && !moreRef.current.contains(event.target as Node)) {
        setMoreOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <header
      className={`fixed inset-x-0 top-0 z-50 flex justify-center transition-all duration-300 ${
        scrolled ? "pt-3 px-4 md:px-6" : "pt-0 px-0"
      }`}
    >
      <div
        aria-hidden="true"
        className={`pointer-events-none absolute inset-x-0 bottom-0 h-px transition-opacity duration-300 ${
          scrolled ? "opacity-0" : "opacity-100"
        }`}
        style={{
          background: "linear-gradient(to right, #38bdf8 0%, #2563eb 100%)",
        }}
      />
      <div
        className={`relative flex w-full items-center justify-between transition-all duration-300 ${
          scrolled
            ? "max-w-6xl rounded-full border border-border bg-white/95 px-6 py-2.5 shadow-[0_8px_30px_rgb(0,0,0,0.06)] backdrop-blur-md"
            : "max-w-[1400px] border-transparent bg-transparent px-8 py-5"
        }`}
      >
        <div className="flex flex-1 items-center">
          <Link className="flex items-center gap-2" href="/">
            <Image
              alt="Raven by SecureMailScope"
              className="h-10 w-auto"
              height={40}
              width={160}
              src="/raven_logo.svg"
              priority
            />
          </Link>
        </div>

        <nav className="hidden items-center gap-1 lg:flex">
          <Link
            className="rounded-pill px-4 py-2 text-base font-medium transition-colors hover:text-primary text-heading"
            href="/"
          >
            Overview
          </Link>
          <Link
            className="rounded-pill px-4 py-2 text-base font-medium transition-colors hover:text-primary text-heading"
            href="#problem"
          >
            The Problem
          </Link>
          <Link
            className="rounded-pill px-4 py-2 text-base font-medium transition-colors hover:text-primary text-heading"
            href="#capabilities"
          >
            Capabilities
          </Link>
          <Link
            className="rounded-pill px-4 py-2 text-base font-medium transition-colors hover:text-primary text-primary font-bold"
            href="/dashboard"
          >
            Console & Dashboard
          </Link>

          <div className="relative" ref={moreRef}>
            <button
              aria-controls="desktop-more-links"
              aria-expanded={moreOpen}
              onClick={() => setMoreOpen(!moreOpen)}
              className="flex items-center gap-1 rounded-pill px-4 py-2 text-base font-medium transition-colors text-heading hover:text-primary"
              type="button"
            >
              Modules
              <svg
                aria-hidden="true"
                className={`h-4 w-4 transition-transform duration-200 ${
                  moreOpen ? "rotate-180" : ""
                }`}
                fill="none"
                height="24"
                stroke="currentColor"
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2.25"
                viewBox="0 0 24 24"
                width="24"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path d="m6 9 6 6 6-6" />
              </svg>
            </button>

            {moreOpen && (
              <div
                id="desktop-more-links"
                className="absolute left-0 top-full mt-2 w-64 overflow-hidden rounded-2xl border border-border bg-white p-2 shadow-xl ring-1 ring-black/5"
              >
                <Link
                  href="/dashboard/posture"
                  onClick={() => setMoreOpen(false)}
                  className="flex flex-col rounded-xl px-4 py-2.5 transition-colors hover:bg-surface-soft"
                >
                  <span className="text-sm font-semibold text-heading">Posture Score (S2)</span>
                  <span className="text-xs text-muted">CI bounded verdict & honest uncertainty</span>
                </Link>
                <Link
                  href="/dashboard/graph"
                  onClick={() => setMoreOpen(false)}
                  className="flex flex-col rounded-xl px-4 py-2.5 transition-colors hover:bg-surface-soft"
                >
                  <span className="text-sm font-semibold text-heading">Delivery Graph (S3)</span>
                  <span className="text-xs text-muted">Hop-by-hop transit & weakest peer</span>
                </Link>
                <Link
                  href="/dashboard/findings"
                  onClick={() => setMoreOpen(false)}
                  className="flex flex-col rounded-xl px-4 py-2.5 transition-colors hover:bg-surface-soft"
                >
                  <span className="text-sm font-semibold text-heading">Findings Explorer (S4)</span>
                  <span className="text-xs text-muted">Byte-level provenance & evidence drawer</span>
                </Link>
                <Link
                  href="/dashboard/reports"
                  onClick={() => setMoreOpen(false)}
                  className="flex flex-col rounded-xl px-4 py-2.5 transition-colors hover:bg-surface-soft"
                >
                  <span className="text-sm font-semibold text-heading">Reports & Playbooks (S5)</span>
                  <span className="text-xs text-muted">SHA-256 seal & vendor config templates</span>
                </Link>
                <Link
                  href="/dashboard/replay"
                  onClick={() => setMoreOpen(false)}
                  className="flex flex-col rounded-xl px-4 py-2.5 transition-colors hover:bg-surface-soft"
                >
                  <span className="text-sm font-semibold text-heading">Incident Replay (S6)</span>
                  <span className="text-xs text-muted">Frame-by-frame wire inspection</span>
                </Link>
              </div>
            )}
          </div>
        </nav>

        <div className="hidden flex-1 items-center justify-end gap-3 lg:flex">
          <Link
            className="inline-flex items-center whitespace-nowrap rounded-pill border border-primary bg-white font-medium text-primary transition-all hover:bg-primary-soft hover:shadow-sm px-5 py-2.5 text-base"
            href="/dashboard"
          >
            Live Ingestion
          </Link>
          <Button href="/dashboard" size="lg">
            Launch Raven
          </Button>
        </div>

        <button
          aria-controls="mobile-navigation"
          aria-expanded={mobileMenuOpen}
          aria-label={mobileMenuOpen ? "Close menu" : "Open menu"}
          onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
          className="flex h-10 w-10 items-center justify-center rounded-pill text-heading lg:hidden"
          type="button"
        >
          {mobileMenuOpen ? (
            <svg
              aria-hidden="true"
              className="h-6 w-6"
              fill="none"
              height="24"
              stroke="currentColor"
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              viewBox="0 0 24 24"
              width="24"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path d="M18 6 6 18" />
              <path d="m6 6 12 12" />
            </svg>
          ) : (
            <svg
              aria-hidden="true"
              className="h-6 w-6"
              fill="none"
              height="24"
              stroke="currentColor"
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              viewBox="0 0 24 24"
              width="24"
              xmlns="http://www.w3.org/2000/svg"
            >
              <path d="M4 5h16" />
              <path d="M4 12h16" />
              <path d="M4 19h16" />
            </svg>
          )}
        </button>
      </div>

      {mobileMenuOpen && (
        <div className="absolute inset-x-4 top-20 z-50 rounded-3xl border border-border bg-white p-6 shadow-2xl lg:hidden">
          <nav className="flex flex-col gap-3">
            <Link
              href="/"
              onClick={() => setMobileMenuOpen(false)}
              className="rounded-xl px-4 py-2.5 text-lg font-medium text-heading transition-colors hover:text-primary"
            >
              Overview
            </Link>
            <Link
              href="#problem"
              onClick={() => setMobileMenuOpen(false)}
              className="rounded-xl px-4 py-2.5 text-lg font-medium text-heading transition-colors hover:text-primary"
            >
              The Problem
            </Link>
            <Link
              href="#capabilities"
              onClick={() => setMobileMenuOpen(false)}
              className="rounded-xl px-4 py-2.5 text-lg font-medium text-heading transition-colors hover:text-primary"
            >
              Capabilities
            </Link>
            <Link
              href="/dashboard"
              onClick={() => setMobileMenuOpen(false)}
              className="rounded-xl px-4 py-2.5 text-lg font-bold text-primary transition-colors hover:text-primary"
            >
              Console & Dashboard
            </Link>
            <div className="border-t border-border my-2" />
            <Link
              href="#faq"
              onClick={() => setMobileMenuOpen(false)}
              className="rounded-xl px-4 py-2 text-base text-body hover:text-primary"
            >
              Technical Specs & FAQ
            </Link>
            <div className="mt-4 flex flex-col gap-3">
              <Link
                className="flex items-center justify-center rounded-pill border border-primary bg-white py-3 text-center text-base font-medium text-primary hover:bg-primary-soft"
                href="/dashboard"
                onClick={() => setMobileMenuOpen(false)}
              >
                Live Ingestion
              </Link>
              <Button href="/dashboard" size="lg" className="w-full justify-center">
                Launch Raven
              </Button>
            </div>
          </nav>
        </div>
      )}
    </header>
  );
}
