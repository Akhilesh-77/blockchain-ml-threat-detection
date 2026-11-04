"""
Unit tests for Zeek log and PCAP feature extraction parsers.
"""

from network.feature_extraction import anonymize_ip, extract_features_from_dict
from network.zeek_parser import parse_zeek_conn_log


def test_ip_anonymization():
    """Verify IP addresses are hashed and PII is removed."""
    ip1 = "192.168.1.100"
    ip2 = "192.168.1.101"
    anon1 = anonymize_ip(ip1)
    anon2 = anonymize_ip(ip2)

    assert anon1.startswith("IP-")
    assert anon2.startswith("IP-")
    assert anon1 != anon2
    assert "192.168" not in anon1
    assert anonymize_ip("-") == "IP-UNKNOWN"


def test_zeek_tsv_parser():
    """Verify standard Zeek conn.log TSV parsing."""
    sample_zeek = """#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents
1762257600.123\tCtest01\t192.168.1.50\t44123\t1.1.1.1\t443\ttcp\tssl\t1.5\t1200\t8000\tSF\tT\tF\t0\tShADadFf\t10\t1600\t15\t8600\t-
"""
    df = parse_zeek_conn_log(sample_zeek)
    assert not df.empty
    assert len(df) == 1
    row = df.iloc[0]
    assert row["session_id"] == "Ctest01"
    assert row["dst_port"] == 443
    assert row["total_fwd_packets"] == 10
    assert row["total_bwd_packets"] == 15
    assert row["total_fwd_bytes"] == 1200.0
    assert row["total_bwd_bytes"] == 8000.0


def test_zeek_json_parser():
    """Verify newline-delimited JSON Zeek log parsing."""
    json_log = '{"ts": 1762257600.5, "uid": "Cjson01", "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.8.8", "id.resp_p": 443, "proto": "tcp", "service": "ssl", "duration": 2.1, "orig_pkts": 8, "resp_pkts": 12, "orig_bytes": 950, "resp_bytes": 12000, "conn_state": "SF"}'
    df = parse_zeek_conn_log(json_log)
    assert not df.empty
    assert df.iloc[0]["session_id"] == "Cjson01"
    assert df.iloc[0]["total_fwd_packets"] == 8
    assert df.iloc[0]["total_bwd_packets"] == 12


def test_feature_extraction_dict():
    """Verify feature dictionary extraction filters and casts properly."""
    raw = {
        "flow_duration": "4.2",
        "total_fwd_packets": 14,
        "non_feature_field": "ignore_me"
    }
    extracted = extract_features_from_dict(raw)
    assert extracted["flow_duration"] == 4.2
    assert extracted["total_fwd_packets"] == 14.0
    assert "non_feature_field" not in extracted

