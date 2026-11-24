export interface VirtualDevice {
  id: string;
  name: string;
  manufacturer: string;
  model: string;
  android_version: string;
  color: string;
  appearance: string;
  security_status: "SECURE" | "MONITORING" | "SUSPICIOUS" | "AT_RISK" | "INFECTED" | "ISOLATED" | "OFFLINE";
  risk_score: number;
  active_threats_count: number;
  battery_level: number;
  wifi_status: string;
  is_isolated: boolean;
  last_activity: string;
  created_at: string;
  updated_at: string;
  installed_apps_count?: number;
}

export interface InstalledApp {
  id: string;
  package_name: string;
  app_name: string;
  category: string;
  version: string;
  install_source: string;
  is_system: boolean;
  is_sideloaded: boolean;
  is_quarantined: boolean;
  risk_score: number;
  security_classification: "SAFE" | "LOW RISK" | "SUSPICIOUS" | "HIGH RISK";
  permissions: string[];
  background_activity: string;
  network_activity: string;
}

export interface DeviceDetail extends VirtualDevice {
  applications: InstalledApp[];
}

export interface SimulationEvent {
  id: string;
  session_id?: string;
  device_id: string;
  app_id?: string;
  event_type: string;
  step_number: number;
  title: string;
  description: string;
  severity: "INFORMATIONAL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  timestamp: string;
  payload?: Record<string, any>;
}

export interface NetworkEvent {
  id: string;
  device_id: string;
  app_id?: string;
  app_name: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  duration: number;
  bytes_sent: number;
  bytes_received: number;
  packet_count: number;
  connection_freq: number;
  classification: "NORMAL" | "SUSPICIOUS" | "MALICIOUS";
  timestamp: string;
}

export interface SecurityIncident {
  id: string;
  device_id: string;
  device_name?: string;
  app_id?: string;
  title: string;
  threat_category: string;
  severity: "INFORMATIONAL" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: "OPEN" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | "FALSE_POSITIVE";
  ml_prediction: string;
  confidence: number;
  risk_score: number;
  description: string;
  recommended_response: string;
  resolution_notes?: string;
  created_at: string;
  updated_at: string;
}

export interface AuditBlock {
  block_index: number;
  record_id: string;
  timestamp: string;
  event_type: string;
  description: string;
  device_id?: string;
  incident_id?: string;
  prev_hash: string;
  current_hash: string;
  nonce: number;
  status: string;
  data_source: string;
  payload: Record<string, any>;
}

export interface BlockchainIntegrity {
  is_valid: boolean;
  total_blocks: number;
  verified_blocks: number;
  tampered_block_index?: number;
  error_type?: string;
  error_message?: string;
  last_verification_time: string;
  latest_hash?: string;
}

export interface MLMetrics {
  model_name: string;
  algorithm: string;
  training_dataset: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  confusion_matrix: number[][];
  classes: string[];
  feature_importances: { feature: string; importance: number }[];
  trained_at: string;
}

export interface MLPrediction {
  prediction: string;
  confidence: number;
  risk_score: number;
  scenario_ground_truth?: string;
  matched_scenario: boolean;
  contributing_features: { feature: string; importance: number; reason: string }[];
  explanation: string;
  model_version: string;
  timestamp: string;
}

export interface NotificationItem {
  id: string;
  title: string;
  message: string;
  severity: "INFO" | "WARNING" | "CRITICAL" | "SUCCESS";
  device_id?: string;
  incident_id?: string;
  is_read: boolean;
  timestamp: string;
}

export interface OverviewStats {
  total_devices: number;
  protected_devices: number;
  infected_devices: number;
  at_risk_devices: number;
  total_incidents: number;
  critical_threats: number;
  network_events_count: number;
  blockchain_blocks_count: number;
  simulation_status: string;
  ml_status: string;
  blockchain_status: string;
  database_status: string;
}

