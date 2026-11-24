import pytest
from fastapi.testclient import TestClient
from backend.main import app

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client

def test_overview_stats(client):
    response = client.get("/api/overview/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_devices" in data
    assert "critical_threats" in data
    assert "blockchain_blocks_count" in data
    assert "blockchain_status" in data
    assert data["total_devices"] >= 1

def test_devices_list_and_quick_add(client):
    # Fetch initial devices
    initial_res = client.get("/api/devices/")
    assert initial_res.status_code == 200
    initial_count = len(initial_res.json())

    # Test quick add 2 devices
    add_res = client.post("/api/devices/quick-add", json={"count": 2})
    assert add_res.status_code == 200
    added_devices = add_res.json()
    assert len(added_devices) == 2

    # Verify count increased by 2
    updated_res = client.get("/api/devices/")
    assert updated_res.status_code == 200
    assert len(updated_res.json()) == initial_count + 2

    # Verify device details and applications
    device_id = added_devices[0]["id"]
    detail_res = client.get(f"/api/devices/{device_id}")
    assert detail_res.status_code == 200
    device_data = detail_res.json()
    assert device_data["name"] == added_devices[0]["name"]
    assert len(device_data["applications"]) >= 1

def test_device_lifecycle_actions(client):
    # Create a test device
    create_res = client.post("/api/devices/", json={
        "name": "Integration Test Phone",
        "manufacturer": "Google",
        "model": "Pixel 8 Pro",
        "android_version": "14.0",
        "battery_level": 88
    })
    assert create_res.status_code == 200
    device = create_res.json()
    device_id = device["id"]

    # Scan device
    scan_res = client.post(f"/api/devices/{device_id}/scan")
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    assert scan_data["verdict"] in ["SAFE", "SUSPICIOUS", "AT_RISK", "INFECTED"]

    # Isolate device
    iso_res = client.post(f"/api/devices/{device_id}/isolate")
    assert iso_res.status_code == 200
    assert iso_res.json()["is_isolated"] is True

    # Reset device
    reset_res = client.post(f"/api/devices/{device_id}/reset")
    assert reset_res.status_code == 200
    assert reset_res.json()["success"] is True
    assert reset_res.json()["security_status"] == "SECURE"

def test_attack_simulation_and_14_step_workflow(client):
    # Fetch a device
    devices = client.get("/api/devices/").json()
    assert len(devices) > 0
    device_id = devices[0]["id"]

    # Run Trojan scenario
    attack_payload = {
        "device_id": device_id,
        "scenario_type": "SCENARIO_A_TROJAN"
    }
    attack_res = client.post("/api/simulation/attack", json=attack_payload)
    assert attack_res.status_code == 200
    data = attack_res.json()

    assert data["success"] is True
    assert data["incident_id"] is not None
    assert data["blockchain_hash"] is not None
    assert data["blockchain_block_index"] is not None
    assert data["ml_prediction"] in ["Suspicious", "Malicious", "Trojan", "HIGH RISK"]
    assert data["risk_score"] > 50.0

    # Verify incident was persisted
    inc_res = client.get(f"/api/incidents/{data['incident_id']}")
    assert inc_res.status_code == 200
    inc_data = inc_res.json()
    assert inc_data["device_id"] == device_id

def test_normal_activity_simulation(client):
    devices = client.get("/api/devices/").json()
    device_id = devices[0]["id"]

    norm_res = client.post(f"/api/simulation/generate-activity/{device_id}")
    assert norm_res.status_code == 200
    data = norm_res.json()
    assert data["success"] is True
    assert data["generated_events_count"] > 0

def test_blockchain_integrity_and_tamper_demo(client):
    # Verify chain integrity
    verify_res = client.get("/api/blockchain/verify")
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["is_valid"] is True
    assert verify_data["total_blocks"] >= 1
    assert verify_data["tampered_block_index"] is None

    # Run tamper demo on block 1
    tamper_res = client.post("/api/blockchain/tamper-demonstration?block_index=1&altered_prediction=TAMPERED_BENIGN")
    assert tamper_res.status_code == 200
    tamper_data = tamper_res.json()
    assert tamper_data["success"] is True
    assert tamper_data["tampered_block_index"] == 1
    assert tamper_data["is_isolated_test_copy"] is True
    assert "Isolated" in tamper_data["message"] or "tamper" in tamper_data["message"].lower()

    # Verify that real chain remained intact
    verify_post_res = client.get("/api/blockchain/verify")
    assert verify_post_res.status_code == 200
    assert verify_post_res.json()["is_valid"] is True

def test_detection_metrics_and_scenarios(client):
    metrics_res = client.get("/api/detection/metrics")
    assert metrics_res.status_code == 200
    data = metrics_res.json()
    assert "accuracy" in data
    assert "precision" in data
    assert "recall" in data
    assert "f1_score" in data
    assert "confusion_matrix" in data
    assert data["accuracy"] > 0.85

    scenarios_res = client.get("/api/detection/scenarios")
    assert scenarios_res.status_code == 200
    scenarios = scenarios_res.json()
    assert len(scenarios) >= 8

def test_network_flows_and_stats(client):
    flows_res = client.get("/api/network/events?limit=10")
    assert flows_res.status_code == 200
    assert isinstance(flows_res.json(), list)

    stats_res = client.get("/api/network/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert "total_flows" in stats
    assert "total_bytes_sent" in stats

def test_reports_export(client):
    # Incidents CSV
    csv_inc = client.get("/api/reports/incidents.csv")
    assert csv_inc.status_code == 200
    assert "text/csv" in csv_inc.headers["content-type"]

    # Network CSV
    csv_net = client.get("/api/reports/network.csv")
    assert csv_net.status_code == 200
    assert "text/csv" in csv_net.headers["content-type"]

    # Blockchain JSON
    json_bc = client.get("/api/reports/blockchain.json")
    assert json_bc.status_code == 200
    assert "blocks" in json_bc.json()
    assert json_bc.json()["chain_valid"] is True

def test_academic_demo_runner(client):
    demo_res = client.post("/api/demo/start")
    assert demo_res.status_code == 200
    data = demo_res.json()
    assert data["success"] is True
    assert "device_1" in data
    assert "device_2" in data
    assert "ml_prediction" in data["device_2"]
