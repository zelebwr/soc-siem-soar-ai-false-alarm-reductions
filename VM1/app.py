"""
SOC AI Inference Service
Endpoints:
  POST /predict/network  -> prefilter + triage pipeline (DDoS/Malware)
  POST /predict/se       -> social engineering model
  POST /predict/unified  -> auto-routes based on alert type
  GET  /health           -> service status

Changes from previous version (updated by Widi):
  - extract_network_features: now expects only 10 features matching
    retrained pkl (down from 78 zero-filled columns).
  - Dual-shape support: handles both real Wazuh alert format
    (fields under "data") and flat curl test format (fields at root).
  - Duration computed from start/end timestamps when "age" not present.
  - /predict/unified routing: replaced test_client() internal calls
    with direct function calls (avoids Flask context overhead).
"""

import json
import joblib
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify
from datetime import datetime

app = Flask(__name__)

# ── Load models at startup (stays in RAM) ──────────────────────
MODEL_DIR = "/home/azureuser/ai_service"

prefilter_model = joblib.load(f"{MODEL_DIR}/prefilter_model.pkl")
triage_model    = joblib.load(f"{MODEL_DIR}/triage_model.pkl")
se_model        = joblib.load(f"{MODEL_DIR}/se_model.pkl")
feature_columns = joblib.load(f"{MODEL_DIR}/feature_columns.pkl")

print(f"[{datetime.now()}] All models loaded. Features: {len(feature_columns)}")


# ── Feature extraction helpers ─────────────────────────────────

def extract_network_features(alert: dict) -> pd.DataFrame:
    """
    Map Suricata EVE alert fields to the 10-feature vector the
    retrained pkl expects.

    Dual-shape support:
      Shape A — real Wazuh alert:  alert["data"]["flow"], alert["data"]["dest_port"]
      Shape B — curl test payload: alert["flow"],          alert["dest_port"]
    """
    # Resolve data container (real Wazuh vs flat test)
    data = alert.get("data") or {}
    flow = data.get("flow") or alert.get("flow") or {}
    tcp  = data.get("tcp")  or alert.get("tcp", {})

    dest_port = int(data.get("dest_port") or alert.get("dest_port", 0))
    pkts_fwd  = int(flow.get("pkts_toserver", 0))
    pkts_bwd  = int(flow.get("pkts_toclient", 0))
    bytes_fwd = int(flow.get("bytes_toserver", 0))
    bytes_bwd = int(flow.get("bytes_toclient", 0))

    # Duration in seconds — prefer "age", else compute from timestamps
    try:
        age_raw = flow.get("age")
        if age_raw is not None:
            dur_s = max(float(age_raw), 0.000001)
        else:
            fmt   = "%Y-%m-%dT%H:%M:%S.%f+0000"
            from datetime import datetime as dt
            dur_s = max(
                (dt.strptime(flow["end"],   fmt) -
                 dt.strptime(flow["start"], fmt)).total_seconds(),
                0.000001
            )
    except Exception:
        dur_s = 0.000001

    total_pkts  = pkts_fwd + pkts_bwd
    total_bytes = bytes_fwd + bytes_bwd

    feat = {
        "Destination Port"            : dest_port,
        "Flow Bytes/s"                : total_bytes / dur_s,
        "Flow Packets/s"              : total_pkts  / dur_s,
        "Total Fwd Packets"           : pkts_fwd,
        "Total Backward Packets"      : pkts_bwd,
        "Total Length of Fwd Packets" : bytes_fwd,
        "Total Length of Bwd Packets" : bytes_bwd,
        "Down/Up Ratio"               : bytes_bwd / max(bytes_fwd, 1),
        "Average Packet Size"         : total_bytes / max(total_pkts, 1),
        "Fwd Packets/s"               : pkts_fwd / dur_s,
    }

    return pd.DataFrame([feat])[feature_columns]


def extract_se_features(alert: dict) -> pd.DataFrame:
    """
    Extract Social Engineering features from Wazuh/GoPhish alert.
    SE model expects exactly 4 features.
    """
    data = alert.get("data") or {}
    rule = alert.get("rule", {})
    desc = rule.get("description", "").lower()

    urgency_keywords = ["critical", "urgent", "immediate", "warning", "alert"]
    urgency_score = min(
        int(rule.get("level", 0)) // 3 +
        sum(1 for kw in urgency_keywords if kw in desc),
        3
    )

    # domain_age_days: check data dict first, then root (Zelig's test passes it at root)
    domain_age_days = int(
        data.get("domain_age_days") or
        alert.get("domain_age_days", 30)
    )

    url = str(data.get("url") or alert.get("url", "")).lower()
    contains_credential_link = 1 if any(
        p in url for p in ["/login", "/submit", "/credential", "/track"]
    ) else 0

    method = str(data.get("method") or alert.get("method", "GET")).upper()
    attachment_present = 1 if method == "POST" else 0

    return pd.DataFrame([{
        "urgency_score":            urgency_score,
        "domain_age_days":          domain_age_days,
        "contains_credential_link": contains_credential_link,
        "attachment_present":       attachment_present,
    }])


def score_to_action(is_anomaly: bool, is_true_positive: bool,
                    rule_level: int) -> str:
    """
    HOTL Level 2 decision logic:
    suppress  → AI confident this is a false positive
    review    → uncertain, human should check
    escalate  → confirmed threat, trigger SOAR response
    """
    if not is_anomaly:
        return "suppress"
    if is_anomaly and not is_true_positive and rule_level < 10:
        return "suppress"
    if is_true_positive or rule_level >= 12:
        return "escalate"
    return "review"


# ── Internal scoring functions (called directly, no Flask overhead) ─────────

def _score_network(alert: dict) -> dict:
    rule_level = int(alert.get("rule", {}).get("level", 0))
    X = extract_network_features(alert)

    is_anomaly   = bool(prefilter_model.predict(X)[0] == 1)
    anomaly_prob = float(prefilter_model.predict_proba(X)[0][1])

    is_tp   = False
    tp_prob = 0.0
    if is_anomaly:
        is_tp   = bool(triage_model.predict(X)[0] == 1)
        tp_prob = float(triage_model.predict_proba(X)[0][1])

    return {
        "model":            "network",
        "is_anomaly":       is_anomaly,
        "anomaly_prob":     round(anomaly_prob, 4),
        "is_true_positive": is_tp,
        "tp_prob":          round(tp_prob, 4),
        "action":           score_to_action(is_anomaly, is_tp, rule_level),
        "rule_level":       rule_level,
    }


def _score_se(alert: dict) -> dict:
    rule_level = int(alert.get("rule", {}).get("level", 0))
    X          = extract_se_features(alert)
    is_phish   = bool(se_model.predict(X)[0] == 1)
    phish_prob = float(se_model.predict_proba(X)[0][1])

    if not is_phish and rule_level < 10:
        action = "suppress"
    elif is_phish or rule_level >= 10:
        action = "escalate"
    else:
        action = "review"

    return {
        "model":       "se",
        "is_phishing": is_phish,
        "phish_prob":  round(phish_prob, 4),
        "action":      action,
        "rule_level":  rule_level,
    }


# ── Endpoints ──────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":   "ok",
        "models":   ["prefilter", "triage", "se"],
        "features": len(feature_columns)
    })


@app.route("/predict/network", methods=["POST"])
def predict_network():
    """DDoS and Malware alert scoring via prefilter → triage pipeline."""
    alert = request.get_json()
    try:
        return jsonify(_score_network(alert))
    except Exception as e:
        return jsonify({"model": "network", "action": "escalate", "error": str(e)}), 200


@app.route("/predict/se", methods=["POST"])
def predict_se():
    """Social Engineering / Phishing alert scoring."""
    alert = request.get_json()
    try:
        return jsonify(_score_se(alert))
    except Exception as e:
        return jsonify({"model": "se", "action": "escalate", "error": str(e)}), 200


@app.route("/predict/unified", methods=["POST"])
def predict_unified():
    """
    Auto-routing endpoint for Shuffle workflow Node 2.
    Detects alert type from rule.groups and calls correct model.
    Uses direct function calls instead of internal test_client().
    """
    alert  = request.get_json()
    groups = alert.get("rule", {}).get("groups", [])

    if isinstance(groups, str):
        groups = [g.strip() for g in groups.split(",")]
    groups_lower = [g.lower() for g in groups]

    try:
        if any(g in groups_lower for g in ["phishing", "web_attack", "social_engineering"]):
            result = _score_se(alert)
            result["routed_to"] = "se"

        elif any(g in groups_lower for g in ["ddos", "malware", "suricata",
                                              "ids", "intrusion", "attack"]):
            result = _score_network(alert)
            result["routed_to"] = "network"

        else:
            rule_level = int(alert.get("rule", {}).get("level", 0))
            if rule_level >= 12:
                action = "escalate"
            elif rule_level >= 8:
                action = "review"
            else:
                action = "suppress"
            result = {
                "model":      "fallback_rule_level",
                "action":     action,
                "rule_level": rule_level,
                "routed_to":  "fallback",
            }

        return jsonify(result)

    except Exception as e:
        return jsonify({"model": "error", "action": "escalate", "error": str(e)}), 200


if __name__ == "__main__":
    # Bind to all interfaces so Shuffle can reach it via 10.1.0.4:5000
    app.run(host="0.0.0.0", port=5000, debug=False)
