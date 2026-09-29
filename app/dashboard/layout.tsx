import React from "react";
import { Metadata } from "next";
import { DashboardProvider } from "@/components/dashboard/DashboardContext";
import { DashboardSidebar } from "@/components/dashboard/DashboardSidebar";
import { DashboardHeader } from "@/components/dashboard/DashboardHeader";

export const metadata: Metadata = {
  title: "Console | Raven SecureMailScope",
  description: "Passive cryptographic security posture assessment platform for enterprise email infrastructure.",
};

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <DashboardProvider>
      <div className="flex h-screen w-full overflow-hidden bg-white text-slate-900 antialiased">
        <DashboardSidebar />
        <div className="flex flex-1 flex-col overflow-hidden min-w-0">
          <DashboardHeader />
          <main className="flex-1 overflow-y-auto bg-surface-soft/70 p-6 md:p-8">
            <div className="mx-auto max-w-7xl">{children}</div>
          </main>
        </div>
      </div>
    </DashboardProvider>
  );
}
