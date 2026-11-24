"use client";

import React, { useState } from "react";
import {
  Bell,
  Smartphone,
  AlertTriangle,
  Play,
  RotateCcw,
  CheckCircle2,
  Clock,
  Sparkles,
  User,
  Plus,
} from "lucide-react";
import { NotificationItem, OverviewStats } from "@/types";

interface TopNavProps {
  stats: OverviewStats | null;
  notifications: NotificationItem[];
  onStartDemo: () => void;
  onOpenAddDevice: () => void;
  onMarkNotificationsRead: () => void;
}

export function TopNav({
  stats,
  notifications,
  onStartDemo,
  onOpenAddDevice,
  onMarkNotificationsRead,
}: TopNavProps) {
  const [showNotifs, setShowNotifs] = useState(false);
  const unreadCount = notifications.filter((n) => !n.is_read).length;

  const now = new Date();
  const timeString = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  return (
    <header className="h-16 bg-[#0d1424]/90 backdrop-blur-md border-b border-slate-800/80 px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Left Telemetry Pills */}
      <div className="flex items-center gap-4">
        {/* Simulation Status */}
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs">
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
          <span className="font-semibold text-slate-300">Simulation:</span>
          <span className="font-mono text-emerald-400 font-bold uppercase">
            {stats?.simulation_status || "RUNNING"}
          </span>
        </div>

        {/* Total Virtual Devices */}
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 text-xs text-slate-300">
          <Smartphone className="w-3.5 h-3.5 text-cyan-400" />
          <span>Devices:</span>
          <span className="font-bold text-white">{stats?.total_devices ?? 0}</span>
        </div>

        {/* Active Incidents */}
        <div
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-xs ${
            (stats?.total_incidents ?? 0) > 0
              ? "bg-red-500/10 border-red-500/30 text-red-400"
              : "bg-slate-900 border-slate-800 text-slate-400"
          }`}
        >
          <AlertTriangle className="w-3.5 h-3.5" />
          <span>Active Threats:</span>
          <span className="font-bold">{stats?.total_incidents ?? 0}</span>
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        {/* Quick Add Device Button */}
        <button
          onClick={onOpenAddDevice}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/40 text-cyan-300 text-xs font-semibold transition-colors"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Add Virtual Device</span>
        </button>

        {/* Guided Demo Button */}
        <button
          onClick={onStartDemo}
          className="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-500 hover:to-indigo-500 text-white text-xs font-bold shadow-md shadow-violet-500/20 transition-all"
        >
          <Sparkles className="w-3.5 h-3.5 text-yellow-300 animate-pulse" />
          <span>Start CyberNex Demo</span>
        </button>

        {/* Simulation Clock */}
        <div className="hidden md:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-400">
          <Clock className="w-3.5 h-3.5 text-slate-500" />
          <span className="font-mono text-slate-200">{timeString} UTC</span>
        </div>

        {/* Notifications Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowNotifs(!showNotifs)}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 relative transition-colors"
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-red-500 text-[10px] font-bold text-white flex items-center justify-center animate-bounce">
                {unreadCount}
              </span>
            )}
          </button>

          {showNotifs && (
            <div className="absolute right-0 mt-2 w-80 bg-[#111827] border border-slate-800 rounded-xl shadow-2xl overflow-hidden z-50">
              <div className="p-3 border-b border-slate-800 flex items-center justify-between bg-slate-900/60">
                <span className="text-xs font-bold text-slate-200">
                  Security Alerts & Notifications ({notifications.length})
                </span>
                {unreadCount > 0 && (
                  <button
                    onClick={() => {
                      onMarkNotificationsRead();
                      setShowNotifs(false);
                    }}
                    className="text-[11px] text-cyan-400 hover:underline"
                  >
                    Mark all read
                  </button>
                )}
              </div>
              <div className="max-h-72 overflow-y-auto divide-y divide-slate-800/60 text-xs">
                {notifications.length === 0 ? (
                  <div className="p-4 text-center text-slate-500">Zero active alerts</div>
                ) : (
                  notifications.map((n) => (
                    <div
                      key={n.id}
                      className={`p-3 transition-colors ${
                        !n.is_read ? "bg-slate-900/80" : "bg-transparent hover:bg-slate-800/30"
                      }`}
                    >
                      <div className="font-semibold text-slate-200 flex items-center gap-1.5 mb-1">
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            n.severity === "CRITICAL"
                              ? "bg-red-500"
                              : n.severity === "WARNING"
                              ? "bg-amber-500"
                              : "bg-cyan-500"
                          }`}
                        ></span>
                        {n.title}
                      </div>
                      <p className="text-slate-400 text-[11px] leading-relaxed">{n.message}</p>
                      <div className="text-[10px] text-slate-500 mt-1.5">
                        {new Date(n.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* Demo User Badge */}
        <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
          <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-bold text-cyan-400">
            SOC
          </div>
        </div>
      </div>
    </header>
  );
}

