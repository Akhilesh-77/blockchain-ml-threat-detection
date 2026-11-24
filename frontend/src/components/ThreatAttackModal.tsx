"use client";

import React, { useState } from "react";
import {
  X,
  ShieldAlert,
  Flame,
  Skull,
  Eye,
  Lock,
  Zap,
  Radio,
  Sliders,
  Play,
  CheckCircle,
} from "lucide-react";
import { VirtualDevice } from "@/types";

interface ThreatAttackModalProps {
  isOpen: boolean;
  onClose: () => void;
  devices: VirtualDevice[];
  selectedDeviceId?: string;
  onExecuteAttack: (payload: {
    device_id: string;
    scenario_type: string;
    custom_params?: any;
  }) => Promise<any>;
}

export function ThreatAttackModal({
  isOpen,
  onClose,
  devices,
  selectedDeviceId,
  onExecuteAttack,
}: ThreatAttackModalProps) {
  const [targetDeviceId, setTargetDeviceId] = useState(
    selectedDeviceId || (devices.length > 0 ? devices[0].id : "")
  );
  const [scenarioType, setScenarioType] = useState("SCENARIO_A_TROJAN");
  const [customSeverity, setCustomSeverity] = useState("HIGH");
  const [customEventsCount, setCustomEventsCount] = useState(5);
  const [loading, setLoading] = useState(false);
  const [attackResult, setAttackResult] = useState<any | null>(null);

  if (!isOpen) return null;

  const scenarios = [
    {
      id: "SCENARIO_A_TROJAN",
      name: "Scenario A: Trojan Simulation",
      badge: "Trojan",
      severity: "HIGH",
      icon: Skull,
      color: "border-red-500/40 text-red-400 bg-red-950/20",
      description:
        "Deceptive utility application that appears legitimate but launches hidden background daemon services and establishes C2 sockets.",
      indicators: ["Accessibility Hook", "Background Service", "Suspicious Port 8443"],
    },
    {
      id: "SCENARIO_B_SPYWARE",
      name: "Scenario B: Spyware Simulation",
      badge: "Spyware",
      severity: "HIGH",
      icon: Eye,
      color: "border-amber-500/40 text-amber-400 bg-amber-950/20",
      description:
        "Simulates unauthorized surveillance accessing microphone audio, continuous background location GPS, and call logs.",
      indicators: ["Microphone Audio", "Background GPS", "Exfiltration Stream"],
    },
    {
      id: "SCENARIO_C_RANSOMWARE",
      name: "Scenario C: Ransomware Simulation",
      badge: "Ransomware",
      severity: "CRITICAL",
      icon: Lock,
      color: "border-red-600/50 text-red-500 bg-red-950/30",
      description:
        "High-risk locker simulation abusing Device Admin rights, attempting screen hijack, and generating rapid file modification bursts.",
      indicators: ["Device Admin Abuse", "Screen Lock Hijack", "Burst Write Ops"],
    },
    {
      id: "SCENARIO_D_ADWARE",
      name: "Scenario D: Adware Simulation",
      badge: "Adware",
      severity: "MEDIUM",
      icon: Flame,
      color: "border-orange-500/40 text-orange-400 bg-orange-950/20",
      description:
        "Aggressive ad-fraud payload triggering excessive full-screen overlays and high-frequency background ad network telemetry.",
      indicators: ["Overlay Abuse", "High Frequency Network", "Ad Fraud C2"],
    },
    {
      id: "SCENARIO_E_UNKNOWN_APK",
      name: "Scenario E: Sideloaded APK Dropper",
      badge: "Dropper",
      severity: "HIGH",
      icon: Zap,
      color: "border-yellow-500/40 text-yellow-400 bg-yellow-950/20",
      description:
        "Simulates unverified APK installation from unknown sources requesting permissions to silently download secondary payloads.",
      indicators: ["Unknown Source", "Package Installer", "Unsigned Certificate"],
    },
    {
      id: "SCENARIO_F_BOTNET",
      name: "Scenario F: Botnet-like Activity",
      badge: "Botnet",
      severity: "HIGH",
      icon: Radio,
      color: "border-cyan-500/40 text-cyan-400 bg-cyan-950/20",
      description:
        "Simulates an infected virtual application participating in coordinated high-frequency automated beaconing to remote C2 endpoints.",
      indicators: ["Automated Beacons", "Port 6667 / 8080", "High Burst Ratio"],
    },
    {
      id: "SCENARIO_G_BANKING_TROJAN",
      name: "Scenario G: Banking Trojan Simulation",
      badge: "Banking Trojan",
      severity: "CRITICAL",
      icon: ShieldAlert,
      color: "border-red-500/50 text-red-400 bg-red-950/30",
      description:
        "Targeted credential theft payload attempting tapjacking screen overlays atop banking apps and intercepting 2FA SMS tokens.",
      indicators: ["Tapjacking Overlay", "SMS Interception", "Keylogging Vector"],
    },
    {
      id: "SCENARIO_H_CUSTOM",
      name: "Scenario H: Custom Threat Scenario",
      badge: "Custom",
      severity: "CONFIGURABLE",
      icon: Sliders,
      color: "border-purple-500/40 text-purple-400 bg-purple-950/20",
      description:
        "Configure custom threat intensity, permission sets, and behavioral parameters to benchmark ML response.",
      indicators: ["User Configured", "Dynamic Features", "Custom Severity"],
    },
  ];

  const handleRunAttack = async () => {
    if (!targetDeviceId) return;
    setLoading(true);
    setAttackResult(null);
    try {
      const res = await onExecuteAttack({
        device_id: targetDeviceId,
        scenario_type: scenarioType,
        custom_params:
          scenarioType === "SCENARIO_H_CUSTOM"
            ? { severity: customSeverity, events_count: customEventsCount }
            : undefined,
      });
      setAttackResult(res);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/75 backdrop-blur-md z-50 flex items-center justify-center p-4">
      <div className="bg-[#111827] border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative max-h-[90vh] flex flex-col">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Modal Header */}
        <div className="flex items-center gap-3 mb-4 shrink-0">
          <div className="w-10 h-10 rounded-xl bg-red-500/20 border border-red-500/40 text-red-400 flex items-center justify-center">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">Simulate Threat Attack</h2>
            <p className="text-xs text-slate-400">
              Trigger a controlled synthetic threat attack scenario on a selected virtual Android device.
            </p>
          </div>
        </div>

        {/* Target Device Selector */}
        <div className="mb-4 shrink-0">
          <label className="text-xs font-semibold text-slate-300 mb-1.5 block">
            Target Virtual Android Device:
          </label>
          <select
            value={targetDeviceId}
            onChange={(e) => setTargetDeviceId(e.target.value)}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
          >
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name} ({d.manufacturer} {d.model}) — [{d.security_status}]
              </option>
            ))}
          </select>
        </div>

        {/* Scenario Selection Grid */}
        <div className="flex-1 overflow-y-auto pr-1 space-y-2 mb-4">
          <label className="text-xs font-semibold text-slate-300 block">
            Select Cyber Threat Scenario (A through H):
          </label>
          {scenarios.map((s) => {
            const Icon = s.icon;
            const isSelected = scenarioType === s.id;
            return (
              <div
                key={s.id}
                onClick={() => setScenarioType(s.id)}
                className={`p-3 rounded-xl border transition-all cursor-pointer ${
                  isSelected
                    ? "bg-slate-900 border-cyan-500 shadow-md shadow-cyan-500/10"
                    : "bg-slate-900/50 border-slate-800/80 hover:border-slate-700"
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-2">
                    <div className={`w-6 h-6 rounded-lg flex items-center justify-center border ${s.color}`}>
                      <Icon className="w-3.5 h-3.5" />
                    </div>
                    <span className="text-xs font-bold text-white">{s.name}</span>
                  </div>
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                      s.severity === "CRITICAL"
                        ? "bg-red-500/20 text-red-400 border-red-500/40"
                        : s.severity === "HIGH"
                        ? "bg-amber-500/20 text-amber-400 border-amber-500/40"
                        : "bg-cyan-500/20 text-cyan-400 border-cyan-500/40"
                    }`}
                  >
                    {s.severity}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed mb-2">{s.description}</p>
                <div className="flex flex-wrap gap-1.5">
                  {s.indicators.map((ind, i) => (
                    <span
                      key={i}
                      className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700"
                    >
                      {ind}
                    </span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>

        {/* Live Attack Execution Feedback */}
        {attackResult && (
          <div className="p-3 mb-4 rounded-xl bg-slate-900/90 border border-emerald-500/40 text-xs">
            <div className="font-bold text-emerald-400 flex items-center gap-1.5 mb-1">
              <CheckCircle className="w-4 h-4" />
              <span>Simulation Execution Complete & Blockchain Audited</span>
            </div>
            <div className="grid grid-cols-2 gap-2 text-[11px] text-slate-300">
              <div>
                <strong>Device Status:</strong>{" "}
                <span className="text-red-400 font-bold">{attackResult.new_device_status}</span>
              </div>
              <div>
                <strong>ML Classification:</strong>{" "}
                <span className="text-amber-400 font-bold">{attackResult.ml_prediction}</span> (
                {Math.round(attackResult.ml_confidence * 100)}% conf)
              </div>
              <div>
                <strong>Incident ID:</strong>{" "}
                <span className="font-mono text-cyan-300">{attackResult.incident_id}</span>
              </div>
              <div>
                <strong>Mined Block:</strong>{" "}
                <span className="font-mono text-cyan-300">Block #{attackResult.blockchain_block_index}</span>
              </div>
            </div>
            <div className="text-[10px] text-slate-400 mt-1.5 font-mono truncate">
              SHA-256 Digest: {attackResult.blockchain_hash}
            </div>
          </div>
        )}

        {/* Action Controls */}
        <div className="flex items-center justify-between pt-3 border-t border-slate-800 shrink-0">
          <div className="text-[11px] text-slate-400">
            Controlled software simulation &bull; Zero real malware executed
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg text-xs font-semibold text-slate-400 hover:text-white"
            >
              Close
            </button>
            <button
              onClick={handleRunAttack}
              disabled={loading || !targetDeviceId}
              className="px-5 py-2 rounded-lg bg-gradient-to-r from-red-600 to-amber-600 hover:from-red-500 hover:to-amber-500 text-white text-xs font-bold shadow-lg shadow-red-600/20 transition-all flex items-center gap-2"
            >
              <Play className="w-3.5 h-3.5 fill-white" />
              <span>{loading ? "Simulating Attack..." : "Simulate Threat Attack"}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

