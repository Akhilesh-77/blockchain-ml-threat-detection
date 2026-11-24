"use client";

import React from "react";
import {
  LayoutDashboard,
  Smartphone,
  Cpu,
  ShieldAlert,
  Layers,
  Activity,
  BrainCircuit,
  Blocks,
  AlertTriangle,
  FileText,
  Settings,
  Sparkles,
} from "lucide-react";

export type NavSection =
  | "overview"
  | "devices"
  | "simulator"
  | "threats"
  | "apps"
  | "network"
  | "ml"
  | "blockchain"
  | "incidents"
  | "reports"
  | "settings";

interface SidebarProps {
  currentSection: NavSection;
  onSelectSection: (section: NavSection) => void;
  activeIncidentsCount?: number;
}

export function Sidebar({
  currentSection,
  onSelectSection,
  activeIncidentsCount = 0,
}: SidebarProps) {
  const navItems = [
    { id: "overview", label: "Overview", icon: LayoutDashboard },
    { id: "devices", label: "Virtual Devices", icon: Smartphone },
    { id: "simulator", label: "Device Simulator", icon: Cpu },
    { id: "threats", label: "Threat Detection", icon: ShieldAlert },
    { id: "apps", label: "Application Security", icon: Layers },
    { id: "network", label: "Network Analysis", icon: Activity },
    { id: "ml", label: "Machine Learning", icon: BrainCircuit },
    { id: "blockchain", label: "Blockchain Audit", icon: Blocks },
    {
      id: "incidents",
      label: "Security Incidents",
      icon: AlertTriangle,
      badge: activeIncidentsCount > 0 ? activeIncidentsCount : undefined,
    },
    { id: "reports", label: "Reports & Export", icon: FileText },
    { id: "settings", label: "Settings & Demo", icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[#0d1424] border-r border-slate-800 flex flex-col justify-between shrink-0 h-screen sticky top-0 select-none z-40">
      <div>
        {/* Brand Header */}
        <div className="p-5 border-b border-slate-800/80">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="font-extrabold text-lg text-white tracking-wider flex items-center gap-1.5">
                CYBERNEX
                <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/50">
                  v2.0
                </span>
              </div>
              <div className="text-[11px] text-cyan-400 font-medium tracking-tight">
                Android Security Simulation
              </div>
            </div>
          </div>
        </div>

        {/* Navigation List */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentSection === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectSection(item.id as NavSection)}
                className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? "bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 shadow-sm"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 border border-transparent"
                }`}
              >
                <div className="flex items-center gap-3">
                  <Icon
                    className={`w-4 h-4 ${
                      isActive ? "text-cyan-400" : "text-slate-400"
                    }`}
                  />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <span className="px-1.5 py-0.5 text-xs font-bold rounded-full bg-red-500/20 text-red-400 border border-red-500/40">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer Info */}
      <div className="p-4 border-t border-slate-800/80 text-xs text-slate-500 bg-slate-900/40">
        <div className="flex items-center justify-between mb-1.5">
          <span className="font-semibold text-slate-400 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            Simulator Active
          </span>
          <span className="text-[10px] text-slate-500">FastAPI &bull; Next.js</span>
        </div>
        <p className="text-[11px] leading-relaxed text-slate-500">
          AI Threat Detection &bull; SHA-256 Ledger &bull; Synthetic Telemetry
        </p>
      </div>
    </aside>
  );
}

