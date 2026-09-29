import type { Metadata } from "next";
import { Anton, Inter_Tight } from "next/font/google";
import "./globals.css";

const interTight = Inter_Tight({
  variable: "--font-inter-tight",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
});

const anton = Anton({
  variable: "--font-display",
  subsets: ["latin"],
  weight: "400",
  display: "swap",
});

export const metadata: Metadata = {
  metadataBase: new URL("https://securemailscope.local"),
  title: "Raven — Passive Email TLS & Cryptographic Posture Intelligence",
  description:
    "Raven is an air-gapped, passive cryptographic security posture platform for email infrastructure. Assess SMTP/IMAP/POP3 encryption, detect TLS stripping, and generate court-grade evidence chains without sending a single packet.",
  icons: {
    icon: "/favicon.ico",
  },
  openGraph: {
    title: "Raven — Cryptographic Posture Intelligence for Email Infrastructure",
    description:
      "Passively assess email cryptographic hygiene, audit TLS enforcement, detect downgrade attacks, and inspect cross-hop delivery paths with deterministic RFC/NIST scoring.",
    images: ["/og-image.png"],
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${interTight.variable} ${anton.variable} h-full antialiased`}
    >
      <body className="min-h-screen bg-surface text-heading font-sans selection:bg-primary/20 selection:text-primary">
        {children}
      </body>
    </html>
  );
}
