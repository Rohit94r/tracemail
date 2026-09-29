"use client";

import React from "react";
import Link from "next/link";

interface ButtonProps {
  children: React.ReactNode;
  href?: string;
  onClick?: () => void;
  size?: "sm" | "md" | "lg";
  className?: string;
  type?: "button" | "submit" | "reset";
  disabled?: boolean;
}

export function Button({
  children,
  href,
  onClick,
  size = "md",
  className = "",
  type = "button",
  disabled = false,
}: ButtonProps) {
  const isLg = size === "lg";
  const paddingClass = isLg
    ? "py-1.5 pl-7 pr-1.5 text-base min-h-[52px]"
    : "py-1.5 pl-5 pr-1.5 text-sm min-h-12";
  const circleSize = isLg ? "h-10 w-10" : "h-9 w-9";

  const content = (
    <>
      <span className="relative inline-block overflow-hidden leading-snug">
        <span className="block transition-transform duration-300 ease-out group-hover:-translate-y-full">
          {children}
        </span>
        <span
          aria-hidden="true"
          className="absolute inset-x-0 top-0 block translate-y-full transition-transform duration-300 ease-out group-hover:translate-y-0"
        >
          {children}
        </span>
      </span>
      <span
        className={`relative flex items-center justify-center overflow-hidden rounded-full bg-white text-primary ${circleSize}`}
      >
        <svg
          aria-hidden="true"
          className="lucide lucide-arrow-right h-4 w-4 absolute transition-transform duration-300 ease-out group-hover:translate-x-6 group-hover:-translate-y-6"
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
          <path d="M5 12h14" />
          <path d="m12 5 7 7-7 7" />
        </svg>
        <svg
          aria-hidden="true"
          className="lucide lucide-arrow-right h-4 w-4 absolute -translate-x-6 translate-y-6 transition-transform duration-300 ease-out group-hover:translate-x-0 group-hover:translate-y-0"
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
          <path d="M5 12h14" />
          <path d="m12 5 7 7-7 7" />
        </svg>
      </span>
    </>
  );

  const baseClasses = `group inline-flex items-center gap-2 whitespace-nowrap rounded-pill bg-primary font-medium text-white shadow-[0_8px_20px_-6px_rgba(37,99,235,0.4)] transition-all hover:shadow-[0_12px_28px_-6px_rgba(37,99,235,0.5)] ${paddingClass} ${className}`;

  if (href) {
    return (
      <Link href={href} className={baseClasses}>
        {content}
      </Link>
    );
  }

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`${baseClasses} ${disabled ? "cursor-not-allowed opacity-50" : ""}`}
    >
      {content}
    </button>
  );
}
