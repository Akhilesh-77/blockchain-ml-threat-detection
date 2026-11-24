"use client";

import React, { useState } from "react";
import {
  Wifi,
  Battery,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Radio,
  Phone,
  MessageSquare,
  Globe,
  MapPin,
  Mail,
  Folder,
  Camera,
  Settings,
  Flame,
  Lock,
  Skull,
  Eye,
  Zap,
} from "lucide-react";
import { DeviceDetail, InstalledApp } from "@/types";

interface PhoneMockupProps {
  device: DeviceDetail;
  onSelectApp?: (app: InstalledApp) => void;
  onScanDevice?: () => void;
}

export function PhoneMockup({ device, onSelectApp, onScanDevice }: PhoneMockupProps) {
  const [selectedAppInternal, setSelectedAppInternal] = useState<InstalledApp | null>(null);

  const getStatusBadge = () => {
    switch (device.security_status) {
      case "INFECTED":
        return {
          bg: "bg-red-500/20 text-red-400 border-red-500/40",
          icon: Skull,
          label: "INFECTED",
        };
      case "AT_RISK":
      case "SUSPICIOUS":
        return {
          bg: "bg-amber-500/20 text-amber-400 border-amber-500/40",
          icon: AlertTriangle,
          label: "AT RISK",
        };
      case "ISOLATED":
        return {
          bg: "bg-purple-500/20 text-purple-400 border-purple-500/40",
          icon: Lock,
          label: "ISOLATED",
        };
      default:
        return {
          bg: "bg-emerald-500/20 text-emerald-400 border-emerald-500/40",
          icon: ShieldCheck,
          label: "SECURE",
        };
    }
  };

  const statusInfo = getStatusBadge();
  const StatusIcon = statusInfo.icon;

  // Icon mapping for installed apps
  const getAppIcon = (app: InstalledApp) => {
    if (app.is_quarantined) return Lock;
    if (app.security_classification === "HIGH RISK") return Skull;
    if (app.security_classification === "SUSPICIOUS") return Flame;

    const lower = app.app_name.toLowerCase();
    if (lower.includes("phone")) return Phone;
    if (lower.includes("message")) return MessageSquare;
    if (lower.includes("chrome") || lower.includes("browser")) return Globe;
    if (lower.includes("map")) return MapPin;
    if (lower.includes("mail")) return Mail;
    if (lower.includes("file")) return Folder;
    if (lower.includes("camera")) return Camera;
    if (lower.includes("bank")) return Shield;
    if (lower.includes("cleaner") || lower.includes("boost")) return Zap;
    if (lower.includes("battery") || lower.includes("saver")) return Eye;
    if (lower.includes("flash") || lower.includes("ad")) return Flame;
    return Settings;
  };

  const currentTime = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

  return (
    <div className="relative flex flex-col items-center select-none">
      {/* Smartphone Chassis */}
      <div className="phone-case">
        {/* Notch / Punch hole */}
        <div className="phone-notch">
          <div className="camera-dot"></div>
        </div>

        {/* Screen */}
        <div className="phone-screen p-3 pt-6">
          {/* Android Status Bar */}
          <div className="flex items-center justify-between text-[11px] text-slate-300 px-2 pt-1 font-medium tracking-tight">
            <span>{currentTime}</span>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-bold text-slate-400">5G</span>
              <Wifi className="w-3.5 h-3.5 text-slate-300" />
              <div className="flex items-center gap-1">
                <span className="text-[10px]">{device.battery_level}%</span>
                <Battery className="w-3.5 h-3.5 text-emerald-400 fill-emerald-400" />
              </div>
            </div>
          </div>

          {/* In-Device Security Status Card */}
          <div className="mt-3 p-2.5 rounded-2xl bg-slate-900/90 border border-slate-800 shadow-lg">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div
                  className={`w-7 h-7 rounded-xl flex items-center justify-center border ${statusInfo.bg}`}
                >
                  <StatusIcon className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-[11px] font-bold text-white leading-none">
                    CyberNex Shield
                  </div>
                  <div className="text-[9px] text-slate-400 mt-0.5">
                    {device.manufacturer} {device.model}
                  </div>
                </div>
              </div>
              <div className="text-right">
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${statusInfo.bg}`}>
                  {statusInfo.label}
                </span>
                <div className="text-[9px] text-slate-400 mt-1 font-mono">
                  Risk: {device.risk_score}/100
                </div>
              </div>
            </div>

            {/* In-device alert banner if infected */}
            {device.active_threats_count > 0 && (
              <div className="mt-2 p-1.5 rounded-lg bg-red-500/15 border border-red-500/30 text-[10px] text-red-300 flex items-center gap-1.5 animate-pulse">
                <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                <span>Active Threat: Anomalous payload detected</span>
              </div>
            )}
          </div>

          {/* Application Grid */}
          <div className="mt-4 flex-1">
            <div className="text-[10px] font-semibold text-slate-400 px-1 mb-2 uppercase tracking-wider flex items-center justify-between">
              <span>Simulated Apps ({device.applications.length})</span>
              <span className="text-cyan-400 text-[9px]">Tap app to inspect</span>
            </div>

            <div className="grid grid-cols-4 gap-2.5 max-h-[340px] overflow-y-auto pr-1">
              {device.applications.map((app) => {
                const Icon = getAppIcon(app);
                const isMalicious = app.security_classification === "HIGH RISK";
                const isSuspicious = app.security_classification === "SUSPICIOUS";
                const isQuarantined = app.is_quarantined;

                return (
                  <button
                    key={app.id}
                    onClick={() => {
                      setSelectedAppInternal(app);
                      if (onSelectApp) onSelectApp(app);
                    }}
                    className="flex flex-col items-center group relative text-center focus:outline-none"
                  >
                    <div
                      className={`w-12 h-12 rounded-2xl flex items-center justify-center transition-transform group-hover:scale-105 border ${
                        isQuarantined
                          ? "bg-purple-950/40 border-purple-800 text-purple-300"
                          : isMalicious
                          ? "bg-red-950/60 border-red-500 text-red-400 shadow-md shadow-red-500/20 animate-pulse"
                          : isSuspicious
                          ? "bg-amber-950/50 border-amber-500 text-amber-400"
                          : "bg-slate-800/90 border-slate-700 text-cyan-400 group-hover:border-cyan-500"
                      }`}
                    >
                      <Icon className="w-5 h-5" />
                    </div>
                    <span className="text-[10px] text-slate-300 mt-1 truncate w-full font-medium leading-tight">
                      {app.app_name}
                    </span>
                    {app.is_sideloaded && !isQuarantined && (
                      <span className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-amber-400 border border-slate-900" />
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Quick in-phone actions */}
          <div className="mt-auto pt-2 pb-4">
            <button
              onClick={onScanDevice}
              className="w-full py-2 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-300 text-xs font-bold transition-all shadow-sm flex items-center justify-center gap-1.5"
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Run On-Device Security Scan</span>
            </button>
          </div>
        </div>

        {/* Home navigation chin */}
        <div className="phone-chin"></div>
      </div>

      {/* Device Identity Sub-label */}
      <div className="mt-3 text-center">
        <div className="text-xs font-bold text-slate-200">{device.name}</div>
        <div className="text-[11px] text-cyan-400 font-mono">{device.id}</div>
      </div>
    </div>
  );
}

