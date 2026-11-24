import {
  AuditBlock,
  BlockchainIntegrity,
  DeviceDetail,
  MLMetrics,
  MLPrediction,
  NetworkEvent,
  NotificationItem,
  OverviewStats,
  SecurityIncident,
  SimulationEvent,
  VirtualDevice,
} from "@/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api";

async function fetchJSON<T>(url: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${url}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options?.headers || {}),
    },
  });
  if (!res.ok) {
    let errDetail = res.statusText;
    try {
      const errJson = await res.json();
      errDetail = errJson.detail || errDetail;
    } catch {}
    throw new Error(errDetail);
  }
  return res.json();
}

export const api = {
  // Overview
  getOverviewStats: () => fetchJSON<OverviewStats>("/overview/stats"),
  getNotifications: () => fetchJSON<NotificationItem[]>("/overview/notifications"),
  markAllNotificationsRead: () => fetchJSON<{ success: boolean }>("/overview/notifications/read-all", { method: "POST" }),

  // Devices
  getDevices: () => fetchJSON<VirtualDevice[]>("/devices"),
  getDevice: (id: string) => fetchJSON<DeviceDetail>(`/devices/${id}`),
  createDevice: (payload: {
    name: string;
    manufacturer: string;
    model: string;
    android_version: string;
    color?: string;
    appearance?: string;
  }) => fetchJSON<VirtualDevice>("/devices", { method: "POST", body: JSON.stringify(payload) }),
  quickAddDevices: (count: number) =>
    fetchJSON<VirtualDevice[]>("/devices/quick-add", { method: "POST", body: JSON.stringify({ count }) }),
  isolateDevice: (id: string) => fetchJSON<{ success: boolean }>(`/devices/${id}/isolate`, { method: "POST" }),
  resetDevice: (id: string) => fetchJSON<{ success: boolean }>(`/devices/${id}/reset`, { method: "POST" }),
  scanDevice: (id: string) => fetchJSON<any>(`/devices/${id}/scan`, { method: "POST" }),
  deleteDevice: (id: string) => fetchJSON<{ success: boolean }>(`/devices/${id}`, { method: "DELETE" }),

  // Simulation
  triggerAttack: (payload: { device_id: string; scenario_type: string; custom_params?: any }) =>
    fetchJSON<any>("/simulation/attack", { method: "POST", body: JSON.stringify(payload) }),
  generateNormalActivity: (deviceId: string) =>
    fetchJSON<{ success: boolean; generated_events_count: number }>(`/simulation/generate-activity/${deviceId}`, {
      method: "POST",
    }),
  quarantineApp: (appId: string) =>
    fetchJSON<{ success: boolean; app_id: string; is_quarantined: boolean }>(`/simulation/quarantine-app/${appId}`, {
      method: "POST",
    }),
  getSimulationEvents: (deviceId: string) => fetchJSON<SimulationEvent[]>(`/simulation/events/${deviceId}`),

  // Network
  getNetworkEvents: (params?: { device_id?: string; classification?: string; limit?: number | string }) => {
    const query = new URLSearchParams(params as any).toString();
    return fetchJSON<NetworkEvent[]>(`/network/events${query ? `?${query}` : ""}`);
  },
  getNetworkStats: () => fetchJSON<any>("/network/stats"),

  // Incidents
  getIncidents: (params?: { status?: string; severity?: string; device_id?: string }) => {
    const query = new URLSearchParams(params as any).toString();
    return fetchJSON<SecurityIncident[]>(`/incidents${query ? `?${query}` : ""}`);
  },
  updateIncidentStatus: (id: string, status: string, notes?: string) =>
    fetchJSON<SecurityIncident>(`/incidents/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ status, resolution_notes: notes }),
    }),

  // ML Detection
  getMLMetrics: () => fetchJSON<MLMetrics>("/detection/metrics"),
  predictThreat: (payload: any) =>
    fetchJSON<MLPrediction>("/detection/predict", { method: "POST", body: JSON.stringify(payload) }),
  getDetectionComparisons: () => fetchJSON<any[]>("/detection/comparison"),

  // Blockchain
  getBlockchainBlocks: () => fetchJSON<AuditBlock[]>("/blockchain/blocks"),
  verifyBlockchain: () => fetchJSON<BlockchainIntegrity>("/blockchain/verify"),
  runTamperDemo: (blockIndex: number, alteredPrediction: string) =>
    fetchJSON<any>(`/blockchain/tamper-demonstration?block_index=${blockIndex}&altered_prediction=${alteredPrediction}`, {
      method: "POST",
    }),

  // Demo
  startDemo: () => fetchJSON<any>("/demo/start", { method: "POST" }),
  resetDemo: () => fetchJSON<any>("/demo/reset", { method: "POST" }),

  // Reports
  exportIncidentsCSVUrl: () => `${API_BASE}/reports/incidents.csv`,
  exportNetworkCSVUrl: () => `${API_BASE}/reports/network.csv`,
  exportBlockchainJSONUrl: () => `${API_BASE}/reports/blockchain.json`,
  exportDeviceJSONUrl: (deviceId: string) => `${API_BASE}/reports/device/${deviceId}.json`,
};
