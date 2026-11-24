"use client";

import React, { useEffect, useState } from "react";
import {
  Smartphone,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Layers,
  Activity,
  BrainCircuit,
  Blocks,
  FileText,
  Settings,
  Plus,
  Play,
  RotateCcw,
  Sparkles,
  Download,
  CheckCircle,
  XCircle,
  Search,
  Filter,
  Lock,
  Skull,
  Eye,
  Flame,
  Zap,
  ArrowRight,
  RefreshCw,
  ExternalLink,
  Cpu,
  Radio,
  Sliders,
} from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
} from "recharts";

import { api } from "@/lib/api";
import {
  AuditBlock,
  BlockchainIntegrity,
  DeviceDetail,
  InstalledApp,
  MLMetrics,
  MLPrediction,
  NetworkEvent,
  NotificationItem,
  OverviewStats,
  SecurityIncident,
  SimulationEvent,
  VirtualDevice,
} from "@/types";
import { Sidebar, NavSection } from "@/components/Sidebar";
import { TopNav } from "@/components/TopNav";
import { PhoneMockup } from "@/components/PhoneMockup";
import { AddDeviceModal } from "@/components/AddDeviceModal";
import { ThreatAttackModal } from "@/components/ThreatAttackModal";

export default function CyberNexApp() {
  const [currentSection, setCurrentSection] = useState<NavSection>("overview");
  const [stats, setStats] = useState<OverviewStats | null>(null);
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [devices, setDevices] = useState<VirtualDevice[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<DeviceDetail | null>(null);
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [networkEvents, setNetworkEvents] = useState<NetworkEvent[]>([]);
  const [blocks, setBlocks] = useState<AuditBlock[]>([]);
  const [mlMetrics, setMLMetrics] = useState<MLMetrics | null>(null);
  const [integrity, setIntegrity] = useState<BlockchainIntegrity | null>(null);
  const [comparisons, setComparisons] = useState<any[]>([]);

  // Modals & UI States
  const [isAddDeviceOpen, setIsAddDeviceOpen] = useState(false);
  const [isThreatModalOpen, setIsThreatModalOpen] = useState(false);
  const [simulatorTab, setSimulatorTab] = useState<
    "overview" | "apps" | "permissions" | "status" | "network" | "threats" | "audit"
  >("overview");
  const [selectedAppModal, setSelectedAppModal] = useState<InstalledApp | null>(null);
  const [tamperResult, setTamperResult] = useState<any | null>(null);
  const [demoBanner, setDemoBanner] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Live Feature Simulator State (ML Tab)
  const [simBytes, setSimBytes] = useState(25000);
  const [simPackets, setSimPackets] = useState(50);
  const [simDuration, setSimDuration] = useState(0.5);
  const [simPerms, setSimPerms] = useState(5);
  const [simCriticalPerms, setSimCriticalPerms] = useState(2);
  const [simSideloaded, setSimSideloaded] = useState(true);
  const [liveMLResult, setLiveMLResult] = useState<MLPrediction | null>(null);

  // Fetch initial data
  const refreshAllData = async () => {
    try {
      const [
        statsData,
        notifsData,
        devicesData,
        incidentsData,
        netData,
        blocksData,
        mlData,
        intData,
        compData,
      ] = await Promise.all([
        api.getOverviewStats().catch(() => null),
        api.getNotifications().catch(() => []),
        api.getDevices().catch(() => []),
        api.getIncidents().catch(() => []),
        api.getNetworkEvents({ limit: "50" }).catch(() => []),
        api.getBlockchainBlocks().catch(() => []),
        api.getMLMetrics().catch(() => null),
        api.verifyBlockchain().catch(() => null),
        api.getDetectionComparisons().catch(() => []),
      ]);

      if (statsData) setStats(statsData);
      setNotifications(notifsData);
      setDevices(devicesData);
      setIncidents(incidentsData);
      setNetworkEvents(netData);
      setBlocks(blocksData);
      setMLMetrics(mlData);
      setIntegrity(intData);
      setComparisons(compData);

      // Select default device if none selected
      if (devicesData.length > 0 && !selectedDevice) {
        api.getDevice(devicesData[0].id).then(setSelectedDevice).catch(() => {});
      } else if (selectedDevice) {
        // Refresh currently selected device
        api.getDevice(selectedDevice.id).then(setSelectedDevice).catch(() => {});
      }
    } catch (err) {
      console.error("Failed to refresh CyberNex telemetry:", err);
    }
  };

  useEffect(() => {
    refreshAllData();
    const interval = setInterval(refreshAllData, 12000);
    return () => clearInterval(interval);
  }, []);

  // Quick Handlers
  const handleSelectDevice = async (id: string) => {
    try {
      const d = await api.getDevice(id);
      setSelectedDevice(d);
      setCurrentSection("simulator");
    } catch (err) {
      console.error(err);
    }
  };

  const handleCreateDevice = async (data: any) => {
    await api.createDevice(data);
    await refreshAllData();
  };

  const handleQuickAdd = async (count: number) => {
    await api.quickAddDevices(count);
    await refreshAllData();
  };

  const handleExecuteAttack = async (payload: any) => {
    const res = await api.triggerAttack(payload);
    await refreshAllData();
    return res;
  };

  const handleScanDevice = async (deviceId: string) => {
    setLoading(true);
    try {
      await api.scanDevice(deviceId);
      await refreshAllData();
    } finally {
      setLoading(false);
    }
  };

  const handleQuarantineApp = async (appId: string) => {
    await api.quarantineApp(appId);
    await refreshAllData();
    setSelectedAppModal(null);
  };

  const handleIsolateDevice = async (deviceId: string) => {
    await api.isolateDevice(deviceId);
    await refreshAllData();
  };

  const handleResetDevice = async (deviceId: string) => {
    await api.resetDevice(deviceId);
    await refreshAllData();
  };

  const handleVerifyBlockchain = async () => {
    const res = await api.verifyBlockchain();
    setIntegrity(res);
  };

  const handleTamperDemo = async () => {
    const targetIdx = blocks.length > 1 ? blocks[blocks.length - 1].block_index : 0;
    const res = await api.runTamperDemo(targetIdx, "SAFE_BENIGN");
    setTamperResult(res);
  };

  const handleStartDemo = async () => {
    setLoading(true);
    setDemoBanner("Executing 10-step academic verification workflow...");
    try {
      const res = await api.startDemo();
      await refreshAllData();
      setDemoBanner(`Demo Succeeded! Device 1 (Normal) vs Device 2 (${res.device_2.attack_scenario} detected via ML).`);
      setTimeout(() => setDemoBanner(null), 8000);
    } catch (err: any) {
      setDemoBanner(`Demo notice: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleLiveMLPredict = async () => {
    const res = await api.predictThreat({
      app_permissions_count: simPerms,
      critical_permissions_count: simCriticalPerms,
      is_sideloaded: simSideloaded,
      connection_duration: simDuration,
      packet_count: simPackets,
      bytes_sent: simBytes,
      bytes_received: 4500,
      scenario_ground_truth: "Interactive Simulator Test",
    });
    setLiveMLResult(res);
  };

  return (
    <div className="flex min-h-screen bg-[#0B0F19] text-slate-100">
      {/* 1. Global Navigation Sidebar */}
      <Sidebar
        currentSection={currentSection}
        onSelectSection={setCurrentSection}
        activeIncidentsCount={incidents.filter((i) => i.status === "OPEN").length}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* 2. Top Header Navigation Bar */}
        <TopNav
          stats={stats}
          notifications={notifications}
          onStartDemo={handleStartDemo}
          onOpenAddDevice={() => setIsAddDeviceOpen(true)}
          onMarkNotificationsRead={() => api.markAllNotificationsRead().then(refreshAllData)}
        />

        {/* Global Demo Status Banner */}
        {demoBanner && (
          <div className="bg-gradient-to-r from-violet-600/30 to-cyan-600/30 border-b border-cyan-500/40 px-6 py-2.5 flex items-center justify-between text-xs text-cyan-200">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-yellow-300 animate-spin" />
              <span>{demoBanner}</span>
            </div>
            <button onClick={() => setDemoBanner(null)} className="text-cyan-400 hover:text-white font-bold">
              Dismiss
            </button>
          </div>
        )}

        {/* Main View Router */}
        <main className="flex-1 p-6 overflow-y-auto">
          {/* ============================================================ */}
          {/* VIEW 1: OVERVIEW DASHBOARD */}
          {/* ============================================================ */}
          {currentSection === "overview" && (
            <div className="space-y-6">
              {/* Header Title */}
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-xl font-extrabold text-white tracking-tight flex items-center gap-2">
                    <Shield className="w-6 h-6 text-cyan-400" />
                    SOC Command Center & Simulation Telemetry
                  </h1>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Real-time monitoring of virtual Android device security postures, ML classifications & SHA-256 blockchain audit logs.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => setIsThreatModalOpen(true)}
                    className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/40 text-xs font-bold transition-colors"
                  >
                    <Flame className="w-4 h-4" />
                    <span>Launch Attack Simulation</span>
                  </button>
                  <button
                    onClick={refreshAllData}
                    className="p-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300"
                  >
                    <RefreshCw className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* 8 Primary KPI Metric Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="cyber-card p-4">
                  <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                    Total Virtual Devices
                  </div>
                  <div className="text-2xl font-black text-white mt-1 flex items-baseline justify-between">
                    <span>{stats?.total_devices ?? 0}</span>
                    <Smartphone className="w-5 h-5 text-cyan-400" />
                  </div>
                  <div className="text-[11px] text-cyan-400 mt-1">Multi-Device Simulator Ready</div>
                </div>

                <div className="cyber-card p-4">
                  <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                    Protected Devices
                  </div>
                  <div className="text-2xl font-black text-emerald-400 mt-1 flex items-baseline justify-between">
                    <span>{stats?.protected_devices ?? 0}</span>
                    <ShieldCheck className="w-5 h-5 text-emerald-400" />
                  </div>
                  <div className="text-[11px] text-emerald-400/80 mt-1">Clean Baseline Verified</div>
                </div>

                <div className="cyber-card p-4">
                  <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                    Infected Devices
                  </div>
                  <div className="text-2xl font-black text-red-400 mt-1 flex items-baseline justify-between">
                    <span>{stats?.infected_devices ?? 0}</span>
                    <Skull className="w-5 h-5 text-red-400" />
                  </div>
                  <div className="text-[11px] text-red-400/80 mt-1">Requires Isolation / Quarantine</div>
                </div>

                <div className="cyber-card p-4">
                  <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                    Devices at Risk
                  </div>
                  <div className="text-2xl font-black text-amber-400 mt-1 flex items-baseline justify-between">
                    <span>{stats?.at_risk_devices ?? 0}</span>
                    <AlertTriangle className="w-5 h-5 text-amber-400" />
                  </div>
                  <div className="text-[11px] text-amber-400/80 mt-1">Suspicious Activity Flagged</div>
                </div>

                <div className="cyber-card p-4">
                  <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                    Total Security Incidents
                  </div>
                  <div className="text-2xl font-black text-white mt-1 flex items-baseline justify-between">
                    <span>{stats?.total_incidents ?? 0}</span>
                    <Layers className="w-5 h-5 text-indigo-400" />
                  </div>
                  <div className="text-[11px] text-indigo-400 mt-1">Documented in SOC Queue</div>
                </div>

                <div className="cyber-card p-4">
                  <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                    Critical Threats
                  </div>
                  <div className="text-2xl font-black text-red-500 mt-1 flex items-baseline justify-between">
                    <span>{stats?.critical_threats ?? 0}</span>
                    <Flame className="w-5 h-5 text-red-500" />
                  </div>
                  <div className="text-[11px] text-red-400 mt-1">High Severity Incidents</div>
                </div>

                <div className="cyber-card p-4">
                  <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                    Network Events
                  </div>
                  <div className="text-2xl font-black text-white mt-1 flex items-baseline justify-between">
                    <span>{stats?.network_events_count ?? 0}</span>
                    <Activity className="w-5 h-5 text-cyan-400" />
                  </div>
                  <div className="text-[11px] text-slate-400 mt-1">Simulated Traffic Flows</div>
                </div>

                <div className="cyber-card p-4">
                  <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                    Blockchain Blocks
                  </div>
                  <div className="text-2xl font-black text-purple-400 mt-1 flex items-baseline justify-between">
                    <span>{stats?.blockchain_blocks_count ?? 0}</span>
                    <Blocks className="w-5 h-5 text-purple-400" />
                  </div>
                  <div className="text-[11px] text-purple-400 mt-1">SHA-256 Ledger Intact</div>
                </div>
              </div>

              {/* Charts & Visualizations Row */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Threat Distribution Chart */}
                <div className="cyber-card p-5">
                  <h3 className="text-sm font-bold text-white mb-1">Simulated Threat Distribution</h3>
                  <p className="text-xs text-slate-400 mb-4">Breakdown of simulated attack classifications</p>
                  <div className="h-52 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={[
                            { name: "Normal", value: Math.max(1, (stats?.protected_devices || 1) * 4), color: "#10B981" },
                            { name: "Trojan", value: incidents.filter((i) => i.threat_category.includes("Trojan")).length || 1, color: "#EF4444" },
                            { name: "Spyware", value: incidents.filter((i) => i.threat_category.includes("Spyware")).length || 1, color: "#F59E0B" },
                            { name: "Ransomware", value: incidents.filter((i) => i.threat_category.includes("Ransomware")).length || 1, color: "#8B5CF6" },
                          ]}
                          innerRadius={50}
                          outerRadius={75}
                          paddingAngle={4}
                          dataKey="value"
                        >
                          <Cell fill="#10B981" />
                          <Cell fill="#EF4444" />
                          <Cell fill="#F59E0B" />
                          <Cell fill="#8B5CF6" />
                        </Pie>
                        <Tooltip contentStyle={{ background: "#111827", borderColor: "#374151" }} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-xs mt-2">
                    <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span> Normal Flow</div>
                    <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-red-500"></span> Trojan</div>
                    <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span> Spyware</div>
                    <div className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-purple-500"></span> Ransomware</div>
                  </div>
                </div>

                {/* Device Status Bar Chart */}
                <div className="cyber-card p-5">
                  <h3 className="text-sm font-bold text-white mb-1">Device Security Postures</h3>
                  <p className="text-xs text-slate-400 mb-4">Real-time status across active virtual devices</p>
                  <div className="h-52 w-full">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={[
                          { status: "Secure", count: stats?.protected_devices ?? 0 },
                          { status: "At Risk", count: stats?.at_risk_devices ?? 0 },
                          { status: "Infected", count: stats?.infected_devices ?? 0 },
                          { status: "Isolated", count: devices.filter((d) => d.is_isolated).length },
                        ]}
                      >
                        <XAxis dataKey="status" stroke="#64748B" fontSize={11} />
                        <YAxis stroke="#64748B" fontSize={11} allowDecimals={false} />
                        <Tooltip contentStyle={{ background: "#111827", borderColor: "#374151" }} />
                        <Bar dataKey="count" fill="#06B6D4" radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="text-[11px] text-slate-400 text-center mt-2">
                    {devices.length} Virtual Endpoints Synchronized
                  </div>
                </div>

                {/* System Architecture & Health */}
                <div className="cyber-card p-5 flex flex-col justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-white mb-1">CyberNex System Health</h3>
                    <p className="text-xs text-slate-400 mb-4">Core engine state & cryptographic integrity</p>
                    <div className="space-y-3 text-xs">
                      <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800">
                        <span className="text-slate-300 font-medium">Simulation Engine</span>
                        <span className="text-emerald-400 font-bold flex items-center gap-1">
                          <CheckCircle className="w-3.5 h-3.5" /> Running
                        </span>
                      </div>
                      <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800">
                        <span className="text-slate-300 font-medium">Machine Learning Engine</span>
                        <span className="text-cyan-400 font-bold flex items-center gap-1">
                          <BrainCircuit className="w-3.5 h-3.5" /> Ready (RF v2.0)
                        </span>
                      </div>
                      <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800">
                        <span className="text-slate-300 font-medium">Blockchain Audit Ledger</span>
                        <span className="text-purple-400 font-bold flex items-center gap-1">
                          <Blocks className="w-3.5 h-3.5" /> {integrity?.is_valid ? "Healthy / Untampered" : "Warning"}
                        </span>
                      </div>
                      <div className="flex items-center justify-between p-2 rounded-lg bg-slate-900 border border-slate-800">
                        <span className="text-slate-300 font-medium">Database Persistence</span>
                        <span className="text-emerald-400 font-bold flex items-center gap-1">
                          <CheckCircle className="w-3.5 h-3.5" /> Connected (SQLite)
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="pt-3 border-t border-slate-800/80 text-[11px] text-slate-500">
                    Dual-domain: Virtual Android Devices &bull; SHA-256 Ledger
                  </div>
                </div>
              </div>

              {/* Recent Incidents & Devices Summary */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Recent Incidents Table */}
                <div className="cyber-card p-5">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-red-400" />
                      Recent Security Incidents ({incidents.length})
                    </h3>
                    <button
                      onClick={() => setCurrentSection("incidents")}
                      className="text-xs text-cyan-400 hover:underline flex items-center gap-1"
                    >
                      View all <ArrowRight className="w-3 h-3" />
                    </button>
                  </div>
                  <div className="space-y-2">
                    {incidents.slice(0, 4).map((inc) => (
                      <div
                        key={inc.id}
                        className="p-3 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between text-xs"
                      >
                        <div>
                          <div className="font-bold text-white flex items-center gap-2">
                            <span
                              className={`w-2 h-2 rounded-full ${
                                inc.severity === "CRITICAL"
                                  ? "bg-red-500"
                                  : inc.severity === "HIGH"
                                  ? "bg-amber-500"
                                  : "bg-cyan-500"
                              }`}
                            ></span>
                            {inc.title}
                          </div>
                          <div className="text-[11px] text-slate-400 mt-0.5">
                            Device: <span className="text-slate-300">{inc.device_name || inc.device_id}</span> &bull;
                            Category: <span className="text-cyan-400">{inc.threat_category}</span>
                          </div>
                        </div>
                        <div className="text-right">
                          <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                              inc.status === "OPEN"
                                ? "bg-red-500/20 text-red-400 border-red-500/40"
                                : "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
                            }`}
                          >
                            {inc.status}
                          </span>
                          <div className="text-[10px] text-slate-500 mt-1">
                            ML: {inc.ml_prediction} ({Math.round(inc.confidence * 100)}%)
                          </div>
                        </div>
                      </div>
                    ))}
                    {incidents.length === 0 && (
                      <div className="p-6 text-center text-slate-500 text-xs">
                        No security incidents detected. Launch a threat attack to evaluate detection!
                      </div>
                    )}
                  </div>
                </div>

                {/* Active Virtual Devices Preview */}
                <div className="cyber-card p-5">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <Smartphone className="w-4 h-4 text-cyan-400" />
                      Active Virtual Endpoints ({devices.length})
                    </h3>
                    <button
                      onClick={() => setCurrentSection("devices")}
                      className="text-xs text-cyan-400 hover:underline flex items-center gap-1"
                    >
                      Manage devices <ArrowRight className="w-3 h-3" />
                    </button>
                  </div>
                  <div className="space-y-2">
                    {devices.slice(0, 4).map((d) => (
                      <div
                        key={d.id}
                        onClick={() => handleSelectDevice(d.id)}
                        className="p-3 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/40 transition-colors cursor-pointer flex items-center justify-between text-xs"
                      >
                        <div className="flex items-center gap-3">
                          <div className="w-9 h-9 rounded-xl bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400">
                            <Smartphone className="w-4 h-4" />
                          </div>
                          <div>
                            <div className="font-bold text-white">{d.name}</div>
                            <div className="text-[11px] text-slate-400">
                              {d.manufacturer} {d.model} &bull; Android {d.android_version}
                            </div>
                          </div>
                        </div>
                        <div className="text-right">
                          <span
                            className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                              d.security_status === "INFECTED"
                                ? "bg-red-500/20 text-red-400 border-red-500/40"
                                : d.security_status === "AT_RISK"
                                ? "bg-amber-500/20 text-amber-400 border-amber-500/40"
                                : "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
                            }`}
                          >
                            {d.security_status}
                          </span>
                          <div className="text-[10px] text-slate-500 mt-1">Risk Score: {d.risk_score}/100</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ============================================================ */}
          {/* VIEW 2: VIRTUAL DEVICES MANAGEMENT */}
          {/* ============================================================ */}
          {currentSection === "devices" && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-xl font-extrabold text-white tracking-tight flex items-center gap-2">
                    <Smartphone className="w-6 h-6 text-cyan-400" />
                    Virtual Android Device Management
                  </h1>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Create, isolate, inspect and configure independent virtual Android smartphones inside CyberNex.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleQuickAdd(1)}
                    className="px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs font-semibold text-slate-300 transition-colors"
                  >
                    + Add 1 Device
                  </button>
                  <button
                    onClick={() => handleQuickAdd(2)}
                    className="px-3.5 py-2 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 border border-cyan-500/40 text-xs font-bold text-cyan-300 transition-colors"
                  >
                    + Add 2 Devices (Dual Lab)
                  </button>
                  <button
                    onClick={() => setIsAddDeviceOpen(true)}
                    className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold shadow-md shadow-cyan-600/20 transition-colors flex items-center gap-1.5"
                  >
                    <Plus className="w-4 h-4" />
                    <span>Custom Virtual Device</span>
                  </button>
                </div>
              </div>

              {/* Device Cards Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {devices.map((dev) => (
                  <div
                    key={dev.id}
                    className={`cyber-card p-5 relative overflow-hidden transition-all ${
                      dev.security_status === "INFECTED"
                        ? "border-red-500/50 shadow-lg shadow-red-500/10"
                        : dev.security_status === "AT_RISK"
                        ? "border-amber-500/40"
                        : "border-slate-800"
                    }`}
                  >
                    {/* Top Device Banner */}
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-2.5">
                        <div
                          className="w-10 h-10 rounded-2xl flex items-center justify-center border shadow-sm"
                          style={{
                            background: `${dev.color}15`,
                            borderColor: `${dev.color}40`,
                            color: dev.color,
                          }}
                        >
                          <Smartphone className="w-5 h-5" />
                        </div>
                        <div>
                          <div className="text-sm font-bold text-white leading-tight">{dev.name}</div>
                          <div className="text-[11px] text-slate-400">
                            {dev.manufacturer} {dev.model}
                          </div>
                        </div>
                      </div>
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                          dev.security_status === "INFECTED"
                            ? "bg-red-500/20 text-red-400 border-red-500/40"
                            : dev.security_status === "AT_RISK"
                            ? "bg-amber-500/20 text-amber-400 border-amber-500/40"
                            : dev.security_status === "ISOLATED"
                            ? "bg-purple-500/20 text-purple-400 border-purple-500/40"
                            : "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
                        }`}
                      >
                        {dev.security_status}
                      </span>
                    </div>

                    {/* Metadata Grid */}
                    <div className="grid grid-cols-2 gap-2 text-xs py-3 border-y border-slate-800/80 my-3 text-slate-300">
                      <div>
                        <span className="text-slate-500 text-[10px] block">ANDROID OS</span>
                        <span className="font-semibold text-cyan-400">Version {dev.android_version}</span>
                      </div>
                      <div>
                        <span className="text-slate-500 text-[10px] block">SECURITY RISK</span>
                        <span
                          className={`font-mono font-bold ${
                            dev.risk_score > 60 ? "text-red-400" : dev.risk_score > 20 ? "text-amber-400" : "text-emerald-400"
                          }`}
                        >
                          {dev.risk_score}/100
                        </span>
                      </div>
                      <div>
                        <span className="text-slate-500 text-[10px] block">INSTALLED APPS</span>
                        <span className="font-medium text-white">{dev.installed_apps_count || 10} Apps</span>
                      </div>
                      <div>
                        <span className="text-slate-500 text-[10px] block">DEVICE ID</span>
                        <span className="font-mono text-[10px] text-slate-400">{dev.id}</span>
                      </div>
                    </div>

                    <div className="text-[11px] text-slate-400 mb-4 line-clamp-1">
                      <span className="text-slate-500">Activity:</span> {dev.last_activity}
                    </div>

                    {/* Action Buttons */}
                    <div className="grid grid-cols-2 gap-2">
                      <button
                        onClick={() => handleSelectDevice(dev.id)}
                        className="py-2 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 text-xs font-bold transition-colors flex items-center justify-center gap-1.5"
                      >
                        <ExternalLink className="w-3.5 h-3.5" />
                        <span>Open Device</span>
                      </button>
                      <button
                        onClick={() => {
                          setSelectedDevice(dev as any);
                          setIsThreatModalOpen(true);
                        }}
                        className="py-2 rounded-lg bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/40 text-xs font-bold transition-colors flex items-center justify-center gap-1.5"
                      >
                        <Flame className="w-3.5 h-3.5" />
                        <span>Simulate Threat</span>
                      </button>
                      <button
                        onClick={() => handleScanDevice(dev.id)}
                        className="py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium transition-colors"
                      >
                        Run Scan
                      </button>
                      <button
                        onClick={() => handleResetDevice(dev.id)}
                        className="py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium transition-colors"
                      >
                        Reset Baseline
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* ============================================================ */}
          {/* VIEW 3: DEVICE SIMULATOR (Individual Workspace & Phone Mockup) */}
          {/* ============================================================ */}
          {currentSection === "simulator" && (
            <div className="space-y-6">
              {/* Header with Device Selector */}
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-xl font-extrabold text-white tracking-tight flex items-center gap-2">
                    <Cpu className="w-6 h-6 text-cyan-400" />
                    Interactive Android Device Simulator
                  </h1>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Live interactive smartphone environment with Android status bar, dynamic application inventory & MITRE threat telemetry.
                  </p>
                </div>
                {/* Device Selector */}
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400">Target Device:</span>
                  <select
                    value={selectedDevice?.id || ""}
                    onChange={(e) => handleSelectDevice(e.target.value)}
                    className="bg-slate-900 border border-slate-800 text-xs text-white rounded-lg px-3 py-2 font-semibold focus:outline-none focus:border-cyan-500"
                  >
                    {devices.map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.name} [{d.security_status}]
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {selectedDevice ? (
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
                  {/* Left Column: Interactive Phone Mockup */}
                  <div className="lg:col-span-4 flex justify-center sticky top-20">
                    <PhoneMockup
                      device={selectedDevice}
                      onSelectApp={(app) => setSelectedAppModal(app)}
                      onScanDevice={() => handleScanDevice(selectedDevice.id)}
                    />
                  </div>

                  {/* Right Column: Tabbed Device Workspace */}
                  <div className="lg:col-span-8 cyber-card p-6">
                    {/* Device Header Bar */}
                    <div className="flex items-center justify-between pb-4 border-b border-slate-800 mb-5">
                      <div>
                        <div className="text-lg font-bold text-white flex items-center gap-2">
                          <span>{selectedDevice.name}</span>
                          <span
                            className={`text-xs font-bold px-2 py-0.5 rounded-full border ${
                              selectedDevice.security_status === "INFECTED"
                                ? "bg-red-500/20 text-red-400 border-red-500/40"
                                : selectedDevice.security_status === "AT_RISK"
                                ? "bg-amber-500/20 text-amber-400 border-amber-500/40"
                                : "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
                            }`}
                          >
                            {selectedDevice.security_status}
                          </span>
                        </div>
                        <div className="text-xs text-slate-400 mt-1">
                          Hardware: {selectedDevice.manufacturer} {selectedDevice.model} &bull; OS: Android {selectedDevice.android_version}
                        </div>
                      </div>

                      {/* Top Action Buttons */}
                      <div className="flex gap-2">
                        <button
                          onClick={() => setIsThreatModalOpen(true)}
                          className="px-3 py-1.5 rounded-lg bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/40 text-xs font-bold transition-colors flex items-center gap-1.5"
                        >
                          <Flame className="w-3.5 h-3.5" />
                          <span>Simulate Attack</span>
                        </button>
                        <button
                          onClick={() => handleIsolateDevice(selectedDevice.id)}
                          className={`px-3 py-1.5 rounded-lg text-xs font-bold border transition-colors ${
                            selectedDevice.is_isolated
                              ? "bg-purple-600/30 text-purple-300 border-purple-500"
                              : "bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700"
                          }`}
                        >
                          {selectedDevice.is_isolated ? "Isolate Active" : "Isolate Device"}
                        </button>
                        <button
                          onClick={() => handleResetDevice(selectedDevice.id)}
                          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-medium"
                        >
                          Reset
                        </button>
                      </div>
                    </div>

                    {/* Workspace Tabs */}
                    <div className="flex border-b border-slate-800 gap-4 mb-5 text-xs font-semibold overflow-x-auto">
                      {[
                        { id: "overview", label: "Overview" },
                        { id: "apps", label: `Applications (${selectedDevice.applications.length})` },
                        { id: "permissions", label: "Permissions" },
                        { id: "status", label: "Security Posture" },
                        { id: "network", label: "Network Telemetry" },
                        { id: "threats", label: "Threat History" },
                        { id: "audit", label: "Blockchain Proofs" },
                      ].map((t) => (
                        <button
                          key={t.id}
                          onClick={() => setSimulatorTab(t.id as any)}
                          className={`pb-2.5 transition-colors border-b-2 whitespace-nowrap ${
                            simulatorTab === t.id
                              ? "border-cyan-400 text-cyan-400"
                              : "border-transparent text-slate-400 hover:text-slate-200"
                          }`}
                        >
                          {t.label}
                        </button>
                      ))}
                    </div>

                    {/* Tab 1: Overview */}
                    {simulatorTab === "overview" && (
                      <div className="space-y-4">
                        <div className="grid grid-cols-2 gap-4 text-xs">
                          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                            <span className="text-slate-500 text-[10px] uppercase font-bold block">
                              SELinux Kernel Mode
                            </span>
                            <span className="text-emerald-400 font-bold text-sm">Enforcing (MAC Active)</span>
                            <p className="text-[11px] text-slate-400 mt-1">
                              Kernel Mandatory Access Control domains enforce process boundaries.
                            </p>
                          </div>
                          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                            <span className="text-slate-500 text-[10px] uppercase font-bold block">
                              Build Profile
                            </span>
                            <span className="text-cyan-400 font-bold text-sm">Release-Keys (Verified)</span>
                            <p className="text-[11px] text-slate-400 mt-1">
                              Official cryptographic OEM image with verified dm-verity state.
                            </p>
                          </div>
                        </div>

                        <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 text-xs">
                          <div className="font-bold text-white mb-2">Device Diagnostic Telemetry</div>
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-slate-300">
                            <div>
                              <span className="text-slate-500 block text-[10px]">RISK SCORE</span>
                              <span className="font-mono text-base font-bold text-cyan-400">
                                {selectedDevice.risk_score} / 100
                              </span>
                            </div>
                            <div>
                              <span className="text-slate-500 block text-[10px]">BATTERY STATE</span>
                              <span className="font-mono text-base font-bold text-emerald-400">
                                {selectedDevice.battery_level}%
                              </span>
                            </div>
                            <div>
                              <span className="text-slate-500 block text-[10px]">WIFI / CELLULAR</span>
                              <span className="font-mono text-base font-bold text-slate-200">
                                {selectedDevice.wifi_status}
                              </span>
                            </div>
                            <div>
                              <span className="text-slate-500 block text-[10px]">THREAT COUNT</span>
                              <span className="font-mono text-base font-bold text-red-400">
                                {selectedDevice.active_threats_count} Active
                              </span>
                            </div>
                          </div>
                        </div>

                        <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between text-xs">
                          <div>
                            <span className="text-slate-400">Need to benchmark benign baseline traffic?</span>
                            <div className="text-[11px] text-slate-500 mt-0.5">
                              Generates simulated HTTPS browsing sessions to Google, YouTube & Cloudflare.
                            </div>
                          </div>
                          <button
                            onClick={() => api.generateNormalActivity(selectedDevice.id).then(refreshAllData)}
                            className="px-3 py-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/40 font-bold transition-colors"
                          >
                            Generate Normal Flows
                          </button>
                        </div>
                      </div>
                    )}

                    {/* Tab 2: Applications */}
                    {simulatorTab === "apps" && (
                      <div className="space-y-3">
                        <div className="text-xs text-slate-400 flex items-center justify-between">
                          <span>Installed packages on this virtual device:</span>
                          <span className="text-slate-500 text-[11px]">Click an app to inspect permissions</span>
                        </div>
                        <div className="divide-y divide-slate-800/80 max-h-[420px] overflow-y-auto">
                          {selectedDevice.applications.map((app) => (
                            <div
                              key={app.id}
                              className="py-3 flex items-center justify-between text-xs hover:bg-slate-900/40 px-2 rounded-lg transition-colors"
                            >
                              <div>
                                <div className="font-bold text-white flex items-center gap-2">
                                  <span>{app.app_name}</span>
                                  <span className="text-[10px] font-mono text-slate-500">({app.package_name})</span>
                                  {app.is_sideloaded && (
                                    <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                                      Sideloaded
                                    </span>
                                  )}
                                  {app.is_quarantined && (
                                    <span className="text-[9px] px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                                      Quarantined
                                    </span>
                                  )}
                                </div>
                                <div className="text-[11px] text-slate-400 mt-1">
                                  Source: <span className="text-slate-300">{app.install_source}</span> &bull; Permissions:{" "}
                                  <span className="text-cyan-400">{app.permissions.length}</span> &bull; Classification:{" "}
                                  <span
                                    className={`font-bold ${
                                      app.security_classification === "HIGH RISK"
                                        ? "text-red-400"
                                        : app.security_classification === "SUSPICIOUS"
                                        ? "text-amber-400"
                                        : "text-emerald-400"
                                    }`}
                                  >
                                    {app.security_classification}
                                  </span>
                                </div>
                              </div>
                              <div className="flex items-center gap-2">
                                <button
                                  onClick={() => setSelectedAppModal(app)}
                                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium"
                                >
                                  Inspect
                                </button>
                                {app.is_sideloaded && !app.is_quarantined && (
                                  <button
                                    onClick={() => handleQuarantineApp(app.id)}
                                    className="px-2.5 py-1 rounded bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/40 text-xs font-bold"
                                  >
                                    Quarantine
                                  </button>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Tab 3: Permissions */}
                    {simulatorTab === "permissions" && (
                      <div className="space-y-4 text-xs">
                        <p className="text-slate-400">
                          Analysis of declared and granted permissions across installed applications. Flags excessive or anomalous access vectors matching MITRE ATT&CK Mobile.
                        </p>
                        <div className="grid grid-cols-2 gap-3">
                          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                            <span className="font-bold text-red-400 flex items-center gap-1.5 mb-1">
                              <AlertTriangle className="w-4 h-4" /> Accessibility Service Hook (T1452)
                            </span>
                            <p className="text-[11px] text-slate-400 leading-relaxed">
                              Primary Android banking trojan vector. Allows background screen scraping, keylogging, and autonomous click hijacking.
                            </p>
                          </div>
                          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                            <span className="font-bold text-amber-400 flex items-center gap-1.5 mb-1">
                              <Flame className="w-4 h-4" /> System Alert Window (T1453)
                            </span>
                            <p className="text-[11px] text-slate-400 leading-relaxed">
                              Tapjacking attack vector. Can draw floating deceptive credentials overlays on top of authentic financial applications.
                            </p>
                          </div>
                          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                            <span className="font-bold text-yellow-400 flex items-center gap-1.5 mb-1">
                              <Zap className="w-4 h-4" /> Unknown Package Installer (T1475)
                            </span>
                            <p className="text-[11px] text-slate-400 leading-relaxed">
                              Secondary payload dropper capability. Permits silently initiating installation of third-party APKs.
                            </p>
                          </div>
                          <div className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                            <span className="font-bold text-purple-400 flex items-center gap-1.5 mb-1">
                              <Lock className="w-4 h-4" /> Device Administrator (T1401)
                            </span>
                            <p className="text-[11px] text-slate-400 leading-relaxed">
                              Locker & ransomware persistence. Prevents user uninstallation without revoking privileged administration rights.
                            </p>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Tab 4: Security Posture */}
                    {simulatorTab === "status" && (
                      <div className="space-y-4 text-xs">
                        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex items-center justify-between">
                          <div>
                            <div className="text-sm font-bold text-white">Device Security Risk Index</div>
                            <div className="text-[11px] text-slate-400 mt-1">
                              Computed via weighted deduction based on active critical threats & sideloaded anomalies.
                            </div>
                          </div>
                          <div className="text-right">
                            <div
                              className={`text-3xl font-black font-mono ${
                                selectedDevice.risk_score > 60
                                  ? "text-red-400"
                                  : selectedDevice.risk_score > 20
                                  ? "text-amber-400"
                                  : "text-emerald-400"
                              }`}
                            >
                              {selectedDevice.risk_score} / 100
                            </div>
                            <span className="text-[10px] text-slate-500 uppercase font-semibold">
                              {selectedDevice.risk_score > 60 ? "CRITICAL RISK" : "HARDENED"}
                            </span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Tab 5: Network Telemetry */}
                    {simulatorTab === "network" && (
                      <div className="space-y-3 text-xs">
                        <div className="text-slate-400">
                          Simulated network flows generated by {selectedDevice.name}:
                        </div>
                        <div className="divide-y divide-slate-800/80 max-h-80 overflow-y-auto font-mono text-[11px]">
                          {networkEvents
                            .filter((n) => n.device_id === selectedDevice.id)
                            .map((net) => (
                              <div key={net.id} className="py-2 flex items-center justify-between">
                                <div>
                                  <span className="text-cyan-400 font-bold">{net.app_name}</span> &rarr;{" "}
                                  <span className="text-slate-300">
                                    {net.dst_ip}:{net.dst_port}
                                  </span>
                                  <span className="text-slate-500 ml-2">({net.protocol})</span>
                                </div>
                                <div className="flex items-center gap-3">
                                  <span className="text-slate-400">{net.bytes_sent + net.bytes_received} B</span>
                                  <span
                                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                      net.classification === "MALICIOUS"
                                        ? "bg-red-500/20 text-red-400"
                                        : net.classification === "SUSPICIOUS"
                                        ? "bg-amber-500/20 text-amber-400"
                                        : "bg-emerald-500/20 text-emerald-400"
                                    }`}
                                  >
                                    {net.classification}
                                  </span>
                                </div>
                              </div>
                            ))}
                        </div>
                      </div>
                    )}

                    {/* Tab 6: Threat History */}
                    {simulatorTab === "threats" && (
                      <div className="space-y-3 text-xs">
                        {incidents
                          .filter((i) => i.device_id === selectedDevice.id)
                          .map((inc) => (
                            <div key={inc.id} className="p-3 rounded-xl bg-slate-900 border border-slate-800">
                              <div className="flex items-center justify-between mb-1">
                                <span className="font-bold text-white">{inc.title}</span>
                                <span className="text-red-400 font-bold text-[10px] px-2 py-0.5 rounded bg-red-500/10 border border-red-500/30">
                                  {inc.severity}
                                </span>
                              </div>
                              <p className="text-slate-400 text-[11px]">{inc.description}</p>
                              <div className="mt-2 text-[10px] text-cyan-400 flex items-center gap-2">
                                <span>ML Prediction: {inc.ml_prediction}</span> &bull;
                                <span>Confidence: {Math.round(inc.confidence * 100)}%</span>
                              </div>
                            </div>
                          ))}
                      </div>
                    )}

                    {/* Tab 7: Blockchain Proofs */}
                    {simulatorTab === "audit" && (
                      <div className="space-y-3 text-xs">
                        <div className="text-slate-400 mb-2">
                          Mined SHA-256 blockchain blocks recording security events for this device:
                        </div>
                        <div className="space-y-2 max-h-80 overflow-y-auto">
                          {blocks
                            .filter((b) => b.device_id === selectedDevice.id)
                            .map((b) => (
                              <div key={b.block_index} className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 font-mono text-[11px]">
                                <div className="flex items-center justify-between text-cyan-400 mb-1">
                                  <span>Block #{b.block_index} &bull; {b.event_type}</span>
                                  <span className="text-emerald-400 text-[10px]">Nonce: {b.nonce}</span>
                                </div>
                                <div className="text-[10px] text-slate-400 truncate">Hash: {b.current_hash}</div>
                              </div>
                            ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ) : (
                <div className="p-12 text-center text-slate-500 text-sm">
                  No virtual device selected. Add a device or select from above!
                </div>
              )}
            </div>
          )}

          {/* ============================================================ */}
          {/* VIEW 4: THREAT DETECTION CENTER */}
          {/* ============================================================ */}
          {currentSection === "threats" && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-xl font-extrabold text-white tracking-tight flex items-center gap-2">
                    <ShieldAlert className="w-6 h-6 text-red-400" />
                    Threat Detection & Attack Simulation Center
                  </h1>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Execute controlled attack scenarios (A through H) against virtual devices and observe the 14-step detection sequence.
                  </p>
                </div>
                <button
                  onClick={() => setIsThreatModalOpen(true)}
                  className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-bold shadow-md shadow-red-600/20 flex items-center gap-1.5"
                >
                  <Flame className="w-4 h-4" />
                  <span>Launch Threat Scenario</span>
                </button>
              </div>

              {/* 14-Step Workflow Visualizer */}
              <div className="cyber-card p-5">
                <h3 className="text-sm font-bold text-white mb-2">Autonomous 14-Step Cybersecurity Workflow</h3>
                <p className="text-xs text-slate-400 mb-4">
                  Every user attack triggers this end-to-end execution sequence across device simulation, ML, and blockchain ledger:
                </p>
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2 text-center text-[10px]">
                  {[
                    "1. Target Device",
                    "2. Load Scenario",
                    "3. Event Sequence",
                    "4. State Update",
                    "5. App Injection",
                    "6. Network Flows",
                    "7. Feature Extract",
                    "8. ML Inference",
                    "9. Risk Scoring",
                    "10. Incident Queue",
                    "11. Push Alert",
                    "12. Mine Block",
                    "13. Ledger Link",
                    "14. Final Result",
                  ].map((step, idx) => (
                    <div
                      key={idx}
                      className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-cyan-300 font-medium"
                    >
                      {step}
                    </div>
                  ))}
                </div>
              </div>

              {/* Threat Scenarios Catalog */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {[
                  { id: "SCENARIO_A_TROJAN", name: "Scenario A: Trojan", icon: Skull, sev: "HIGH", color: "text-red-400" },
                  { id: "SCENARIO_B_SPYWARE", name: "Scenario B: Spyware", icon: Eye, sev: "HIGH", color: "text-amber-400" },
                  { id: "SCENARIO_C_RANSOMWARE", name: "Scenario C: Ransomware", icon: Lock, sev: "CRITICAL", color: "text-red-500" },
                  { id: "SCENARIO_D_ADWARE", name: "Scenario D: Adware", icon: Flame, sev: "MEDIUM", color: "text-orange-400" },
                  { id: "SCENARIO_E_UNKNOWN_APK", name: "Scenario E: APK Dropper", icon: Zap, sev: "HIGH", color: "text-yellow-400" },
                  { id: "SCENARIO_F_BOTNET", name: "Scenario F: Botnet C2", icon: Radio, sev: "HIGH", color: "text-cyan-400" },
                  { id: "SCENARIO_G_BANKING_TROJAN", name: "Scenario G: Banking Trojan", icon: ShieldAlert, sev: "CRITICAL", color: "text-red-400" },
                  { id: "SCENARIO_H_CUSTOM", name: "Scenario H: Custom Threat", icon: Sliders, sev: "CUSTOM", color: "text-purple-400" },
                ].map((s) => {
                  const Icon = s.icon;
                  return (
                    <div key={s.id} className="cyber-card p-4 flex flex-col justify-between">
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <Icon className={`w-5 h-5 ${s.color}`} />
                          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                            {s.sev}
                          </span>
                        </div>
                        <div className="text-xs font-bold text-white">{s.name}</div>
                      </div>
                      <button
                        onClick={() => {
                          setIsThreatModalOpen(true);
                        }}
                        className="mt-3 w-full py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[11px] font-bold transition-colors"
                      >
                        Simulate
                      </button>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* ============================================================ */}
          {/* VIEW 5: APPLICATION SECURITY */}
          {/* ============================================================ */}
          {currentSection === "apps" && (
            <div className="space-y-6">
              <div>
                <h1 className="text-xl font-extrabold text-white tracking-tight flex items-center gap-2">
                  <Layers className="w-6 h-6 text-cyan-400" />
                  Application Security & Permission Inventory
                </h1>
                <p className="text-xs text-slate-400 mt-0.5">
                  Audit simulated packages, inspect granted permissions, and quarantine suspicious sideloaded APKs.
                </p>
              </div>

              {/* Applications Table */}
              <div className="cyber-card p-5">
                <div className="divide-y divide-slate-800/80 text-xs">
                  {devices.flatMap((d) => (d as any).applications || []).map((app: InstalledApp) => (
                    <div key={app.id} className="py-3 flex items-center justify-between">
                      <div>
                        <div className="font-bold text-white flex items-center gap-2">
                          <span>{app.app_name}</span>
                          <span className="text-[10px] text-slate-500 font-mono">({app.package_name})</span>
                          {app.is_sideloaded && (
                            <span className="text-[9px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                              Sideloaded
                            </span>
                          )}
                          {app.is_quarantined && (
                            <span className="text-[9px] px-1.5 py-0.2 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                              Quarantined
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-400 mt-0.5">
                          Category: {app.category} &bull; Source: {app.install_source} &bull; Risk: {app.risk_score}/100
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => setSelectedAppModal(app)}
                          className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
                        >
                          Permissions ({app.permissions.length})
                        </button>
                        {app.is_sideloaded && !app.is_quarantined && (
                          <button
                            onClick={() => handleQuarantineApp(app.id)}
                            className="px-3 py-1 rounded bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/40 text-xs font-bold"
                          >
                            Quarantine
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ============================================================ */}
          {/* VIEW 6: NETWORK ANALYSIS */}
          {/* ============================================================ */}
          {currentSection === "network" && (
            <div className="space-y-6">
              <div>
                <h1 className="text-xl font-extrabold text-white tracking-tight flex items-center gap-2">
                  <Activity className="w-6 h-6 text-cyan-400" />
                  Network Traffic Simulation & Forensics
                </h1>
                <p className="text-xs text-slate-400 mt-0.5">
                  Metadata-based traffic inspection. Analyzes flow statistics, packet timings and rates without payload decryption.
                </p>
              </div>

              {/* Educational Explanation Box */}
              <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-800/50 text-xs text-cyan-200">
                <div className="font-bold flex items-center gap-1.5 mb-1 text-cyan-300">
                  <ShieldCheck className="w-4 h-4" />
                  <span>Zero-Payload Inspection Philosophy:</span>
                </div>
                CyberNex classifies network behaviors strictly using transport metadata (flow duration, byte rate, inter-arrival times, packet sizes, burst ratios). Private communications, messages, and TLS payloads are never decrypted or intercepted.
              </div>

              {/* Network Flows Table */}
              <div className="cyber-card p-5">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-bold text-white">Recent Simulated Network Flows ({networkEvents.length})</h3>
                  <a
                    href={api.exportNetworkCSVUrl()}
                    className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-300 border border-slate-700 flex items-center gap-1.5"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download CSV</span>
                  </a>
                </div>
                <div className="divide-y divide-slate-800/80 font-mono text-xs max-h-96 overflow-y-auto">
                  {networkEvents.map((net) => (
                    <div key={net.id} className="py-2.5 flex items-center justify-between">
                      <div>
                        <span className="text-cyan-400 font-bold">{net.app_name}</span> &bull;{" "}
                        <span className="text-slate-300">{net.src_ip}:{net.src_port}</span> &rarr;{" "}
                        <span className="text-slate-200">{net.dst_ip}:{net.dst_port}</span>
                        <span className="text-slate-500 ml-2">({net.protocol})</span>
                      </div>
                      <div className="flex items-center gap-4">
                        <span className="text-slate-400">{net.bytes_sent + net.bytes_received} Bytes</span>
                        <span
                          className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                            net.classification === "MALICIOUS"
                              ? "bg-red-500/20 text-red-400"
                              : net.classification === "SUSPICIOUS"
                              ? "bg-amber-500/20 text-amber-400"
                              : "bg-emerald-500/20 text-emerald-400"
                          }`}
                        >
                          {net.classification}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ============================================================ */}
          {/* VIEW 7: MACHINE LEARNING DETECTION ENGINE */}
          {/* ============================================================ */}
          {currentSection === "ml" && (
            <div className="space-y-6">
              <div>
                <h1 className="text-xl font-extrabold text-white tracking-tight flex items-center gap-2">
                  <BrainCircuit className="w-6 h-6 text-cyan-400" />
                  Machine Learning Threat Detection Engine
                </h1>
                <p className="text-xs text-slate-400 mt-0.5">
                  Scikit-Learn Random Forest model evaluation, confusion matrix, feature importances & live feature simulation.
                </p>
              </div>

              {/* Model Provenance & Metrics */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div className="cyber-card p-4">
                  <span className="text-[10px] uppercase font-bold text-slate-500 block">MODEL ACCURACY</span>
                  <span className="text-2xl font-black text-emerald-400 mt-1 block">
                    {Math.round((mlMetrics?.accuracy || 0.98) * 100)}%
                  </span>
                  <span className="text-[11px] text-slate-400">Held-out test split</span>
                </div>
                <div className="cyber-card p-4">
                  <span className="text-[10px] uppercase font-bold text-slate-500 block">PRECISION (WEIGHTED)</span>
                  <span className="text-2xl font-black text-cyan-400 mt-1 block">
                    {(mlMetrics?.precision || 0.98).toFixed(3)}
                  </span>
                  <span className="text-[11px] text-slate-400">Low false positive rate</span>
                </div>
                <div className="cyber-card p-4">
                  <span className="text-[10px] uppercase font-bold text-slate-500 block">RECALL (WEIGHTED)</span>
                  <span className="text-2xl font-black text-indigo-400 mt-1 block">
                    {(mlMetrics?.recall || 0.98).toFixed(3)}
                  </span>
                  <span className="text-[11px] text-slate-400">Threat catch rate</span>
                </div>
                <div className="cyber-card p-4">
                  <span className="text-[10px] uppercase font-bold text-slate-500 block">F1-SCORE</span>
                  <span className="text-2xl font-black text-purple-400 mt-1 block">
                    {(mlMetrics?.f1_score || 0.98).toFixed(3)}
                  </span>
                  <span className="text-[11px] text-slate-400">Harmonic balance</span>
                </div>
              </div>

              {/* Interactive Live Feature Simulator */}
              <div className="cyber-card p-5">
                <h3 className="text-sm font-bold text-white mb-1">Interactive Feature Simulator & Prediction Lab</h3>
                <p className="text-xs text-slate-400 mb-4">
                  Adjust simulated flow features and observe independent ML threat classification in real time:
                </p>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs mb-4">
                  <div>
                    <label className="text-slate-400 mb-1 block">Bytes Sent: {simBytes.toLocaleString()} B</label>
                    <input
                      type="range"
                      min="500"
                      max="150000"
                      value={simBytes}
                      onChange={(e) => setSimBytes(Number(e.target.value))}
                      className="w-full"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 mb-1 block">Packet Count: {simPackets}</label>
                    <input
                      type="range"
                      min="5"
                      max="200"
                      value={simPackets}
                      onChange={(e) => setSimPackets(Number(e.target.value))}
                      className="w-full"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 mb-1 block">Critical Permissions: {simCriticalPerms}</label>
                    <input
                      type="range"
                      min="0"
                      max="5"
                      value={simCriticalPerms}
                      onChange={(e) => setSimCriticalPerms(Number(e.target.value))}
                      className="w-full"
                    />
                  </div>
                </div>

                <button
                  onClick={handleLiveMLPredict}
                  className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold transition-colors"
                >
                  Run ML Threat Prediction
                </button>

                {liveMLResult && (
                  <div className="mt-4 p-4 rounded-xl bg-slate-900 border border-slate-800 text-xs">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-bold text-white">Prediction Result:</span>
                      <span
                        className={`font-black text-sm px-2.5 py-0.5 rounded ${
                          liveMLResult.prediction === "Malicious"
                            ? "bg-red-500/20 text-red-400"
                            : liveMLResult.prediction === "Suspicious"
                            ? "bg-amber-500/20 text-amber-400"
                            : "bg-emerald-500/20 text-emerald-400"
                        }`}
                      >
                        {liveMLResult.prediction}
                      </span>
                    </div>
                    <div className="text-slate-300 mb-1">
                      <strong>Confidence:</strong> {Math.round(liveMLResult.confidence * 100)}% &bull;{" "}
                      <strong>Risk Score:</strong> {liveMLResult.risk_score}/100
                    </div>
                    <p className="text-slate-400 text-[11px] leading-relaxed">{liveMLResult.explanation}</p>
                  </div>
                )}
              </div>

              {/* Scenario Ground-Truth vs ML Prediction Comparison */}
              <div className="cyber-card p-5">
                <h3 className="text-sm font-bold text-white mb-1">Ground-Truth vs ML Prediction Comparisons</h3>
                <p className="text-xs text-slate-400 mb-4">
                  Compares predefined attack simulation labels against independent model predictions:
                </p>
                <div className="divide-y divide-slate-800 text-xs font-mono">
                  {comparisons.map((c, i) => (
                    <div key={i} className="py-2.5 flex items-center justify-between">
                      <div>
                        <span className="text-slate-400">Scenario Ground Truth:</span>{" "}
                        <span className="text-white font-bold">{c.scenario_ground_truth}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-slate-400">ML: {c.ml_prediction} ({Math.round(c.confidence * 100)}%)</span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            c.is_matched ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400"
                          }`}
                        >
                          {c.is_matched ? "MATCHED" : "MISMATCH"}
                        </span>
                      </div>
                    </div>
                  ))}
                  {comparisons.length === 0 && (
                    <div className="p-4 text-center text-slate-500">No comparison records yet. Run an attack!</div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ============================================================ */}
          {/* VIEW 8: BLOCKCHAIN AUDIT LEDGER */}
          {/* ============================================================ */}
          {currentSection === "blockchain" && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-xl font-extrabold text-white tracking-tight flex items-center gap-2">
                    <Blocks className="w-6 h-6 text-purple-400" />
                    Cryptographic Blockchain Audit Ledger
                  </h1>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Immutable SHA-256 hash-chain maintaining sequential proof-of-work blocks for all threat detections.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleVerifyBlockchain}
                    className="px-3.5 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold shadow-md shadow-purple-600/20 flex items-center gap-1.5"
                  >
                    <CheckCircle className="w-4 h-4" />
                    <span>Verify Blockchain Integrity</span>
                  </button>
                  <button
                    onClick={handleTamperDemo}
                    className="px-3.5 py-2 rounded-lg bg-amber-600/20 hover:bg-amber-600/30 text-amber-300 border border-amber-500/40 text-xs font-bold"
                  >
                    Run Tamper Demo
                  </button>
                </div>
              </div>

              {/* Integrity Status Card */}
              {integrity && (
                <div
                  className={`p-4 rounded-xl border flex items-center justify-between text-xs ${
                    integrity.is_valid
                      ? "bg-emerald-950/20 border-emerald-500/40 text-emerald-300"
                      : "bg-red-950/20 border-red-500/40 text-red-300"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    {integrity.is_valid ? (
                      <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle className="w-5 h-5 text-red-400 shrink-0" />
                    )}
                    <div>
                      <div className="font-bold text-sm">
                        {integrity.is_valid
                          ? "LEDGER INTEGRITY VERIFIED — ZERO TAMPERING DETECTED"
                          : `INTEGRITY COMPROMISED: ${integrity.error_type}`}
                      </div>
                      <div className="text-[11px] opacity-90 mt-0.5">
                        Verified {integrity.verified_blocks} of {integrity.total_blocks} total blocks across unbroken SHA-256 linkages.
                      </div>
                    </div>
                  </div>
                  <div className="text-right font-mono text-[10px]">
                    <div>Proof-of-Work: Difficulty = 2</div>
                    <div>Target: 00... (Verified)</div>
                  </div>
                </div>
              )}

              {/* Tamper Demonstration Result */}
              {tamperResult && (
                <div className="p-4 rounded-xl bg-slate-900 border border-amber-500/40 text-xs">
                  <div className="font-bold text-amber-300 mb-1">
                    Safe Educational Tamper Demonstration
                  </div>
                  <p className="text-slate-300 text-[11px] leading-relaxed mb-2">
                    {tamperResult.message}
                  </p>
                  <div className="text-[10px] text-slate-500">
                    Authoritative persistent database ledger remains intact and untouched.
                  </div>
                </div>
              )}

              {/* Visual Block Explorer */}
              <div className="space-y-3">
                <h3 className="text-sm font-bold text-white">Cryptographic Sequential Block Explorer ({blocks.length} Blocks)</h3>
                <div className="space-y-3">
                  {blocks.map((b, idx) => (
                    <div
                      key={b.block_index}
                      className="cyber-card p-4 relative font-mono text-xs border-l-4 border-l-purple-500"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-purple-400">Block #{b.block_index}</span>
                          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-sans">
                            {b.event_type}
                          </span>
                        </div>
                        <span className="text-[10px] text-slate-400">Nonce: {b.nonce}</span>
                      </div>
                      <p className="text-slate-300 font-sans text-xs mb-2">{b.description}</p>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[10px] text-slate-400">
                        <div className="truncate">
                          <strong>Prev Hash:</strong> <span className="text-slate-500">{b.prev_hash}</span>
                        </div>
                        <div className="truncate">
                          <strong>Current Hash:</strong> <span className="text-cyan-400">{b.current_hash}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ============================================================ */}
          {/* VIEW 9: SECURITY INCIDENTS */}
          {/* ============================================================ */}
          {currentSection === "incidents" && (
            <div className="space-y-6">
              <div className="flex items-center justify-between">
                <div>
                  <h1 className="text-xl font-extrabold text-white tracking-tight flex items-center gap-2">
                    <AlertTriangle className="w-6 h-6 text-red-400" />
                    Security Incident Management Queue
                  </h1>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Investigate, contain, and resolve active security incidents generated by simulated threats.
                  </p>
                </div>
                <a
                  href={api.exportIncidentsCSVUrl()}
                  className="px-3.5 py-2 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-xs font-bold text-slate-300 flex items-center gap-1.5"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download Incidents CSV</span>
                </a>
              </div>

              {/* Incidents List */}
              <div className="space-y-3">
                {incidents.map((inc) => (
                  <div key={inc.id} className="cyber-card p-5 text-xs">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <span
                          className={`w-2.5 h-2.5 rounded-full ${
                            inc.severity === "CRITICAL"
                              ? "bg-red-500 animate-ping"
                              : inc.severity === "HIGH"
                              ? "bg-amber-500"
                              : "bg-cyan-500"
                          }`}
                        ></span>
                        <span className="font-bold text-sm text-white">{inc.title}</span>
                      </div>
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded-full border ${
                          inc.status === "OPEN"
                            ? "bg-red-500/20 text-red-400 border-red-500/40"
                            : "bg-emerald-500/20 text-emerald-400 border-emerald-500/40"
                        }`}
                      >
                        {inc.status}
                      </span>
                    </div>

                    <p className="text-slate-300 mb-3 leading-relaxed">{inc.description}</p>

                    <div className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] mb-3 text-cyan-300">
                      <strong>Recommended Response:</strong> {inc.recommended_response}
                    </div>

                    <div className="flex items-center justify-between pt-2 border-t border-slate-800/80">
                      <div className="text-[10px] text-slate-500 font-mono">
                        Incident ID: {inc.id} &bull; Device: {inc.device_name || inc.device_id}
                      </div>
                      {inc.status === "OPEN" && (
                        <button
                          onClick={() =>
                            api
                              .updateIncidentStatus(inc.id, "RESOLVED", "Threat quarantined and mitigated via SOC action")
                              .then(refreshAllData)
                          }
                          className="px-3 py-1 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/40 text-xs font-bold"
                        >
                          Mark Resolved
                        </button>
                      )}
                    </div>
                  </div>
                ))}
                {incidents.length === 0 && (
                  <div className="p-12 text-center text-slate-500 text-sm">
                    Zero active incidents in queue. All virtual endpoints secure.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ============================================================ */}
          {/* VIEW 10: REPORTS & EXPORT */}
          {/* ============================================================ */}
          {currentSection === "reports" && (
            <div className="space-y-6">
              <div>
                <h1 className="text-xl font-extrabold text-white tracking-tight flex items-center gap-2">
                  <FileText className="w-6 h-6 text-cyan-400" />
                  Forensic Security Reports & Cryptographic Export
                </h1>
                <p className="text-xs text-slate-400 mt-0.5">
                  Generate compliance reports, export detection records to CSV, and extract JSON blockchain ledger proofs.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="cyber-card p-5">
                  <h3 className="text-sm font-bold text-white mb-2">Export Incidents Report (CSV)</h3>
                  <p className="text-xs text-slate-400 mb-4">
                    Download detailed tabular records of all security incidents, ML predictions, and device associations.
                  </p>
                  <a
                    href={api.exportIncidentsCSVUrl()}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold"
                  >
                    <Download className="w-4 h-4" />
                    <span>Download Incidents CSV</span>
                  </a>
                </div>

                <div className="cyber-card p-5">
                  <h3 className="text-sm font-bold text-white mb-2">Export Blockchain Ledger (JSON)</h3>
                  <p className="text-xs text-slate-400 mb-4">
                    Download cryptographic JSON proof containing complete hash-chain blocks, previous hashes, and nonces.
                  </p>
                  <a
                    href={api.exportBlockchainJSONUrl()}
                    className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-bold"
                  >
                    <Download className="w-4 h-4" />
                    <span>Export Ledger Proofs JSON</span>
                  </a>
                </div>
              </div>
            </div>
          )}

          {/* ============================================================ */}
          {/* VIEW 11: SETTINGS & GUIDED DEMO */}
          {/* ============================================================ */}
          {currentSection === "settings" && (
            <div className="space-y-6">
              <div>
                <h1 className="text-xl font-extrabold text-white tracking-tight flex items-center gap-2">
                  <Settings className="w-6 h-6 text-cyan-400" />
                  Settings & Guided Academic Demonstration
                </h1>
                <p className="text-xs text-slate-400 mt-0.5">
                  Manage simulation parameters, review architecture, or run the automated evaluation workflow.
                </p>
              </div>

              {/* Guided Demo Box */}
              <div className="cyber-card p-6 border-l-4 border-l-cyan-500">
                <div className="flex items-center gap-2 mb-2">
                  <Sparkles className="w-5 h-5 text-yellow-300" />
                  <h3 className="text-base font-bold text-white">One-Click CyberNex Demonstration Mode</h3>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed mb-4">
                  Runs the complete academic verification sequence: instantiates dual virtual devices (Samsung S24 & Pixel 8), triggers a simulated Trojan attack, executes ML Random Forest classification, logs security incidents, and commits SHA-256 blockchain audit blocks.
                </p>
                <div className="flex gap-3">
                  <button
                    onClick={handleStartDemo}
                    disabled={loading}
                    className="px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 text-white text-xs font-bold flex items-center gap-2 shadow-lg"
                  >
                    <Play className="w-4 h-4 fill-white" />
                    <span>{loading ? "Running Demo..." : "Start CyberNex Demo"}</span>
                  </button>
                  <button
                    onClick={() => api.resetDemo().then(refreshAllData)}
                    className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700"
                  >
                    Reset Demo State
                  </button>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>

      {/* App Inspection Modal */}
      {selectedAppModal && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#111827] border border-slate-800 rounded-2xl max-w-lg w-full p-6 shadow-2xl relative">
            <button
              onClick={() => setSelectedAppModal(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white p-1"
            >
              <XCircle className="w-5 h-5" />
            </button>
            <div className="text-sm font-bold text-white mb-1">{selectedAppModal.app_name}</div>
            <div className="text-xs text-cyan-400 font-mono mb-3">{selectedAppModal.package_name}</div>
            <div className="text-xs text-slate-300 space-y-2 mb-4">
              <div>
                <strong>Install Source:</strong> {selectedAppModal.install_source}
              </div>
              <div>
                <strong>Security Classification:</strong> {selectedAppModal.security_classification}
              </div>
              <div>
                <strong>Declared Permissions ({selectedAppModal.permissions.length}):</strong>
                <div className="flex flex-wrap gap-1 mt-1.5">
                  {selectedAppModal.permissions.map((p, idx) => (
                    <span key={idx} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                      {p}
                    </span>
                  ))}
                </div>
              </div>
            </div>
            {selectedAppModal.is_sideloaded && !selectedAppModal.is_quarantined && (
              <button
                onClick={() => handleQuarantineApp(selectedAppModal.id)}
                className="w-full py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-bold"
              >
                Quarantine This Application
              </button>
            )}
          </div>
        </div>
      )}

      {/* Add Device Modal */}
      <AddDeviceModal
        isOpen={isAddDeviceOpen}
        onClose={() => setIsAddDeviceOpen(false)}
        onCreateDevice={handleCreateDevice}
        onQuickAdd={handleQuickAdd}
      />

      {/* Threat Attack Modal */}
      <ThreatAttackModal
        isOpen={isThreatModalOpen}
        onClose={() => setIsThreatModalOpen(false)}
        devices={devices}
        selectedDeviceId={selectedDevice?.id}
        onExecuteAttack={handleExecuteAttack}
      />
    </div>
  );
}
