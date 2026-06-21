---
date_created: 2026-06-22T02:28
date_modified: 2026-06-22T02:40
---

# Full Architecture Plan

## Index

```
1. System Architecture & VM Layout
2. Network Topology
3. Technology Stack
4. Data & Alert Flow (SIEM)
5. AI Pipeline (Training → Inference)
6. SOAR Workflow (Shuffle)
7. Attack Simulation Plan
8. SOC Tier Mapping
9. Configuration Specifications
10. GitHub Repository Structure
```

Executing Item 1 only per pacing rule. Await command to proceed.

---

# Item 1: System Architecture & VM Layout

```
┌─────────────────────────────────────────────────────┐
│                   AZURE CENTRAL INDIA               │
│                                                     │
│  ┌──────────────────────────────────────────────┐   │
│  │ VM1 — wazuh-manager                          │   │
│  │ Standard_B2als_v2 (2vCPU / 4GB RAM)          │   │
│  │                                              │   │
│  │  ├── Wazuh Manager        ~400MB             │   │
│  │  ├── Wazuh Indexer        ~512MB (capped)    │   │
│  │  ├── Wazuh Dashboard      ~300MB             │   │
│  │  ├── Shuffle SOAR         ~800MB             │   │
│  │  └── AI Inference Service ~150MB             │   │
│  │                           ────────           │   │
│  │                   Total:  ~2.16GB ✓          │   │
│  └──────────────────────────────────────────────┘   │
│                         ↕ port 1514/1515 (TLS)      │
│  ┌──────────────────────────────────────────────┐   │
│  │ VM2 — wazuh-victim                           │   │
│  │ Standard_B2als_v2 (2vCPU / 4GB RAM)          │   │
│  │                                              │   │
│  │  ├── Wazuh Agent          ~200MB             │   │
│  │  ├── Apache2 (HTTP)       ~100MB             │   │
│  │  ├── OpenSSH (SSH)        ~50MB              │   │
│  │  ├── Vsftpd (FTP)         ~50MB              │   │
│  │  └── GoPhish              ~200MB             │   │
│  │                           ────────           │   │
│  │                   Total:  ~600MB ✓           │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
          ↕ Azure Public IP (port 80, 22, 21, 3333)
┌─────────────────────────────────────────────────────┐
│  LOCAL MACHINE (Attacker)                           │
│  Windows + Kali WSL2                                │
│                                                     │
│  ├── hping3          → DDoS simulation              │
│  ├── Metasploit      → Malware/exploitation         │
│  └── Browser/curl    → Social engineering clicks    │
└─────────────────────────────────────────────────────┘
```

---

## VM1 Component RAM Budget (Hard Cap Enforcement)

```bash
# /etc/wazuh-indexer/jvm.options — enforce heap cap
-Xms512m
-Xmx512m

# Shuffle runs in Docker — cap container memory
# docker-compose.yml override:
services:
  shuffle-backend:
    mem_limit: 300m
  shuffle-frontend:
    mem_limit: 150m
  shuffle-orborus:
    mem_limit: 200m
  shuffle-database:
    mem_limit: 150m
```

---

## SOC Tier Mapping to This Architecture

|SOC Tier|Function|Implemented By|
|---|---|---|
|Tier 1: System Security|Log collection, normalization|Wazuh Agent → Manager|
|Tier 1-2: Alert Management|Alert correlation, false alarm filtering|Wazuh Rules + AI Isolation Forest|
|Tier 2-3: Threat Management|Threat classification, escalation|AI scoring + Shuffle decision logic|
|Tier 3-4: Response & Recovery|Automated + human-confirmed response|Shuffle SOAR workflows|

---

## AI Autonomy Mapping (Level 2 HOTL)

```
Alert score LOW  (anomaly_score < 0.3) + rule_level < 8
→ AI suppresses autonomously → logged, human can audit

Alert score MED  (0.3 ≤ anomaly_score < 0.7) OR rule_level 8–11
→ AI tags as "review" → pushed to Wazuh dashboard queue
→ Human reviews async

Alert score HIGH (anomaly_score ≥ 0.7) OR rule_level ≥ 12
→ AI escalates → Shuffle triggers response workflow
→ Destructive actions (block IP, isolate host) → human confirmation gate via Shuffle approval step
```

---

## Full System Data Flow

**Three distinct flows — mapped separately for clarity.**

---

## Flow 1: Normal Alert Pipeline (No Attack)

```
VM2 Wazuh Agent
├── Monitors: filesystem, logs, processes, network (FIM, SCA, syscall)
├── Collects: /var/log/auth.log, /var/log/apache2/*, syslog
└── Sends raw events → VM1:1514 (TLS encrypted)
         ↓
VM1 Wazuh Manager
├── Decodes raw event → extracts fields (src_ip, user, action, timestamp)
├── Matches against ruleset → assigns rule_id + rule_level (1–15)
├── Generates alert JSON
└── Writes to wazuh-indexer (OpenSearch)
         ↓
VM1 AI Inference Service (Flask API, local)
├── Wazuh Manager calls POST /predict after each alert
├── Extracts features: [rule_level, rule_id, src_ip_entropy,
│   alert_frequency_1min, bytes_sent, port, protocol, hour_of_day]
├── Isolation Forest scores alert → anomaly_score (0.0–1.0)
└── Returns: {label: "normal/anomaly", score: 0.xx, action: "suppress/review/escalate"}
         ↓
VM1 Wazuh Manager (receives AI response)
├── score < 0.3 + level < 8  → tags alert "AI_SUPPRESSED" → stored, not escalated
├── score 0.3–0.7            → tags alert "AI_REVIEW"     → visible on dashboard
└── score ≥ 0.7 OR level ≥ 12 → tags alert "AI_ESCALATE" → triggers Shuffle webhook
         ↓
VM1 Wazuh Dashboard
└── SOC analyst sees only REVIEW + ESCALATE tagged alerts
    SUPPRESSED alerts still queryable for audit
```

---

## Flow 2: Attack Detection Pipeline (Active Attack from Local Machine)

```
LOCAL MACHINE (Kali WSL2)
└── Executes attack → VM2 public IP
         ↓
VM2 Network Interface
├── Receives attack traffic
└── OS + services generate logs:
    ├── DDoS      → /var/log/syslog (connection flood), netstat anomaly
    ├── Malware   → /var/log/auth.log (exploit attempt), new process spawn
    └── Phishing  → Apache access log (GoPhish click), credential POST
         ↓
VM2 Wazuh Agent
├── FIM detects filesystem changes (malware dropper)
├── Log analysis detects auth failures, flood patterns
├── SCA detects config changes
└── Sends event stream → VM1:1514 (burst of events during attack)
         ↓
VM1 Wazuh Manager
├── Correlates burst of events → fires high-level rules
│   ├── rule 40101: SYN flood detected
│   ├── rule 5710: SSH brute force
│   └── rule 31103: Web attack detected
├── Generates multiple alerts in short window
└── Each alert → sent to AI Inference Service
         ↓
VM1 AI Inference Service
├── Isolation Forest sees: high frequency, high rule_level,
│   unusual hour, high src_ip_entropy → anomaly_score ≥ 0.7
└── Returns: {label: "anomaly", score: 0.87, action: "escalate"}
         ↓
VM1 Wazuh Manager
└── Fires Shuffle webhook → POST to Shuffle:5001/webhook/<hook_id>
    payload: {alert_id, rule_id, src_ip, score, action, timestamp}
         ↓
VM1 Shuffle SOAR
├── Workflow triggered by webhook
├── Evaluates action field:
│   ├── action = "escalate" + rule involves network flood
│   │   → HOTL autonomous: executes block_ip workflow
│   │   → VM2: adds iptables DROP rule for src_ip (via SSH action)
│   │   → Logs action to Shuffle audit trail
│   │
│   ├── action = "escalate" + rule involves admin privilege change
│   │   → HOTL human gate: sends approval request
│   │   → Email/Slack notification to SOC analyst
│   │   → Waits for confirm/deny → then executes or discards
│   │
│   └── action = "review"
│       → Creates ticket in dashboard queue, no automated action
         ↓
VM1 Wazuh Dashboard
└── SOC analyst sees:
    ├── Real-time alert feed (ESCALATE + REVIEW only)
    ├── AI score column per alert
    ├── Shuffle response action taken (or pending approval)
    └── Full suppressed alert audit log accessible on demand
```

---

## Flow 3: AI Training Pipeline (Offline, Pre-Deployment)

```
VM1 Wazuh Indexer (OpenSearch)
└── Export historical alerts after attack simulations
    → GET /wazuh-alerts-*/_search → alerts.json
         ↓
Manual Labeling Step (team does this once)
├── Attack window alerts  → label: 1 (true positive)
├── Normal window alerts  → label: 0 (true negative / false positive candidates)
└── Export labeled_alerts.csv
         ↓
Google Colab / Local Machine
├── Load labeled_alerts.csv
├── Feature engineering:
│   ├── alert_frequency_per_minute (rolling count)
│   ├── rule_level (direct)
│   ├── src_ip_entropy (repeated vs distributed IPs)
│   ├── hour_of_day (behavioral baseline)
│   ├── bytes_sent, protocol, dst_port
│   └── is_known_scanner (IP reputation flag, local list)
│
├── Phase 1: Train Isolation Forest (unsupervised)
│   └── fit on normal-window alerts only → learns baseline
│
├── Phase 2: Train Random Forest (supervised, for benchmark)
│   └── fit on full labeled dataset → compare F1 vs Isolation Forest
│
├── Evaluate both:
│   ├── Precision, Recall, F1-score
│   ├── False Positive Rate (primary metric)
│   └── Confusion matrix
│
└── Serialize winner → joblib.dump(model, "isolation_forest_v1.pkl")
         ↓
GitHub Repository
└── git push → model.pkl committed to /models/ directory
         ↓
VM1 (deployment)
├── git pull → model.pkl lands at /opt/ai_service/models/
├── Flask API service restarts → loads new model
└── Inference service live → Flow 1 & 2 resume with updated model
```

---

## Cross-Flow Dependency Map

```
Local Machine ──attack──→ VM2 Agent ──events──→ VM1 Manager
                                                      │
                                          ┌───────────┼───────────┐
                                          ↓           ↓           ↓
                                    AI Service   Indexer    Dashboard
                                          │           │           │
                                          └─────→ Shuffle ←───────┘
                                                      │
                                          ┌───────────┴───────────┐
                                          ↓                       ↓
                                   Auto Response          Human Approval Gate
                                   (HOTL trivial)         (HOTL privileged)
```

---

## Item 2: Network Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                    AZURE CENTRAL INDIA REGION                   │
│                    Virtual Network (VNet)                       │
│                    CIDR: 10.0.0.0/16                           │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Subnet: 10.0.1.0/24                        │   │
│  │                                                         │   │
│  │  ┌──────────────────────────┐                          │   │
│  │  │ VM1 — wazuh-manager      │                          │   │
│  │  │ Private IP: 10.0.1.4     │                          │   │
│  │  │ Public IP:  <VM1_PUB_IP> │                          │   │
│  │  │                          │                          │   │
│  │  │ NSG Inbound Rules:       │                          │   │
│  │  │ 22   ← local machine IP  │ (SSH admin only)         │   │
│  │  │ 1514 ← 10.0.1.5 only    │ (Wazuh agent events)     │   │
│  │  │ 1515 ← 10.0.1.5 only    │ (Wazuh agent enrollment) │   │
│  │  │ 443  ← local machine IP  │ (Dashboard HTTPS)        │   │
│  │  │ 5001 ← 10.0.1.4 only    │ (Shuffle webhook)        │   │
│  │  │ 5000 ← 10.0.1.4 only    │ (AI Flask API)           │   │
│  │  │                          │                          │   │
│  │  │ NSG Outbound Rules:      │                          │   │
│  │  │ 22   → 10.0.1.5         │ (Shuffle SSH response)   │   │
│  │  │ ALL  → 10.0.1.5         │ (SOAR action calls)      │   │
│  │  └──────────────────────────┘                          │   │
│  │              ↕ 10.0.1.0/24 internal                    │   │
│  │  ┌──────────────────────────┐                          │   │
│  │  │ VM2 — wazuh-victim       │                          │   │
│  │  │ Private IP: 10.0.1.5     │                          │   │
│  │  │ Public IP:  <VM2_PUB_IP> │                          │   │
│  │  │                          │                          │   │
│  │  │ NSG Inbound Rules:       │                          │   │
│  │  │ 22   ← local machine IP  │ (SSH admin)              │   │
│  │  │ 22   ← 10.0.1.4         │ (Shuffle response action)│   │
│  │  │ 80   ← ANY              │ (Apache — attack surface) │   │
│  │  │ 21   ← ANY              │ (FTP — attack surface)   │   │
│  │  │ 3333 ← ANY              │ (GoPhish — phishing sim) │   │
│  │  │                          │                          │   │
│  │  │ NSG Outbound Rules:      │                          │   │
│  │  │ 1514 → 10.0.1.4         │ (Wazuh events)           │   │
│  │  │ 1515 → 10.0.1.4         │ (Wazuh enrollment)       │   │
│  │  └──────────────────────────┘                          │   │
│  └─────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                         ↕ public internet
┌─────────────────────────────────────────────────────────────────┐
│  LOCAL MACHINE — Attacker + Admin                               │
│  Windows + Kali WSL2                                            │
│  Public IP: <YOUR_IP> (static or noted per session)            │
│                                                                 │
│  Outbound attack traffic → VM2 public IP                        │
│  ├── port 80   (HTTP flood / web exploit)                       │
│  ├── port 22   (SSH brute force)                                │
│  ├── port 21   (FTP exploit)                                    │
│  └── port 3333 (GoPhish interaction)                            │
│                                                                 │
│  Admin access:                                                  │
│  ├── SSH → VM1:22  (management)                                 │
│  └── HTTPS → VM1:443 (Wazuh Dashboard)                         │
└─────────────────────────────────────────────────────────────────┘
```

---

### Critical Network Security Notes

```
1. Ports 1514/1515 locked to private subnet ONLY
   → Wazuh agent traffic never exposed to public internet

2. Shuffle webhook port 5001 locked to VM1 private IP only
   → SOAR cannot be triggered externally

3. AI Flask API port 5000 locked to VM1 private IP only
   → Inference endpoint internal only, not externally callable

4. VM2 attack surface ports (80, 21, 3333) open to ANY
   → Intentional — required for realistic attack simulation
   → Document this explicitly in report as controlled lab condition

5. SSH admin access (port 22 on VM1) restricted to your local machine IP
   → Prevents brute force from other sources while attack sim runs on VM2
```

---

## Item 3: Technology Stack

### VM1 — Wazuh Manager Stack

|Layer|Technology|Version|Purpose|
|---|---|---|---|
|OS|Ubuntu Server 22.04 LTS|22.04|Base OS|
|SIEM Core|Wazuh Manager|4.7.x|Alert correlation, rule engine|
|SIEM Storage|Wazuh Indexer (OpenSearch)|4.7.x|Alert persistence, search|
|SIEM UI|Wazuh Dashboard|4.7.x|Analyst interface|
|SOAR|Shuffle|Latest|Workflow automation|
|SOAR Runtime|Docker + Docker Compose|24.x|Shuffle container orchestration|
|AI Runtime|Python 3.10|3.10|Model inference environment|
|AI Framework|Scikit-learn|1.4.x|Isolation Forest + Random Forest|
|AI API|Flask|3.x|Inference REST endpoint|
|AI Serialization|Joblib|1.3.x|model.pkl persistence|
|Data Processing|Pandas + NumPy|latest|Feature engineering|
|Comm Protocol|Wazuh API (REST)|4.7.x|Manager ↔ AI service integration|

---

### VM2 — Victim Stack

|Layer|Technology|Version|Purpose|
|---|---|---|---|
|OS|Ubuntu Server 22.04 LTS|22.04|Base OS|
|SIEM Agent|Wazuh Agent|4.7.x|Log + event collection|
|Web Service|Apache2|2.4.x|HTTP attack surface|
|Remote Access|OpenSSH|8.9.x|SSH brute force surface|
|File Transfer|Vsftpd|3.x|FTP attack surface|
|Phishing Sim|GoPhish|0.12.x|Social engineering simulation|
|Log Sources|auth.log, syslog, apache2/access.log|—|Wazuh agent monitored paths|

---

### Local Machine — Attacker Stack (Kali WSL2)

|Tool|Purpose|Attack Type|
|---|---|---|
|hping3|SYN/UDP flood|DDoS|
|slowloris|HTTP connection exhaustion|DDoS|
|Metasploit Framework|Exploitation framework|Malware|
|msfvenom|Payload generation|Malware|
|Hydra|SSH/FTP brute force|Credential attack|
|curl / Python scripts|GoPhish interaction simulation|Social Engineering|
|Wireshark|Attack traffic verification|Validation|

---

### Integration Layer

```
Wazuh Manager
    → Active Response scripts → calls VM2 via SSH (iptables block)
    → Wazuh API → Shuffle webhook trigger (POST /webhook)
    → Wazuh API → AI Flask API (POST /predict)

Shuffle SOAR
    → Wazuh API connector → queries/updates alerts
    → SSH action → VM2 iptables (autonomous block, trivial)
    → Email/Webhook notifier → human approval gate (privileged actions)

AI Service (Flask)
    → Receives alert JSON from Wazuh integration script
    → Returns prediction JSON to integration script
    → Integration script updates alert tag via Wazuh API
```

---

## Item 4: SIEM Alert Flow Configuration

### 4.1 Wazuh Agent Configuration (VM2)

```xml
<!-- /var/ossec/etc/ossec.conf on VM2 — monitored log sources -->
<ossec_config>
  <client>
    <!-- Point agent to VM1 private IP only, never public -->
    <server>
      <address>10.0.1.4</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>

  <!-- File Integrity Monitoring — detects malware dropper -->
  <syscheck>
    <frequency>300</frequency>
    <directories realtime="yes" check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories realtime="yes" check_all="yes">/tmp,/var/tmp</directories>
    <!-- /tmp is primary malware staging directory -->
  </syscheck>

  <!-- Log sources Wazuh agent reads and forwards -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
    <!-- SSH brute force, sudo abuse, auth failures -->
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/apache2/access.log</location>
    <!-- HTTP flood, web exploit attempts -->
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
    <!-- General system events, process spawns -->
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/vsftpd.log</location>
    <!-- FTP access attempts -->
  </localfile>

  <!-- Active response receiver — Shuffle/Wazuh sends block commands here -->
  <active-response>
    <disabled>no</disabled>
  </active-response>
</ossec_config>
```

---

### 4.2 Wazuh Manager Custom Rules (VM1)

```xml
<!-- /var/ossec/etc/rules/local_rules.xml on VM1 -->
<group name="local,soc_project,">

  <!-- DDoS Detection: HTTP flood threshold -->
  <rule id="100001" level="12">
    <if_matched_sid>31103</if_matched_sid>
    <!-- fires when Apache rule 31103 triggers >50 times in 60s -->
    <same_source_ip/>
    <description>DDoS: HTTP flood detected from same source IP</description>
    <mitre>
      <id>T1498</id>
    </mitre>
    <group>ddos,high_priority,</group>
  </rule>

  <!-- DDoS Detection: SYN flood via syslog netfilter -->
  <rule id="100002" level="12">
    <if_sid>1002</if_sid>
    <match>SYN flood</match>
    <description>DDoS: SYN flood detected via kernel netfilter log</description>
    <mitre>
      <id>T1498.001</id>
    </mitre>
    <group>ddos,high_priority,</group>
  </rule>

  <!-- Malware Detection: suspicious file in /tmp -->
  <rule id="100003" level="13">
    <if_sid>554</if_sid>
    <!-- 554 = FIM file added -->
    <field name="file">/tmp/</field>
    <description>Malware: executable file created in /tmp directory</description>
    <mitre>
      <id>T1059</id>
    </mitre>
    <group>malware,high_priority,</group>
  </rule>

  <!-- Malware Detection: Metasploit reverse shell pattern -->
  <rule id="100004" level="14">
    <if_sid>5710</if_sid>
    <match>Failed password</match>
    <same_source_ip/>
    <description>Malware: brute force followed by auth success — possible shell</description>
    <mitre>
      <id>T1078</id>
    </mitre>
    <group>malware,critical,</group>
  </rule>

  <!-- Social Engineering: GoPhish credential harvest -->
  <rule id="100005" level="10">
    <if_sid>31103</if_sid>
    <url>/track</url>
    <description>Social Engineering: phishing link clicked — GoPhish tracker hit</description>
    <mitre>
      <id>T1566.002</id>
    </mitre>
    <group>phishing,medium_priority,</group>
  </rule>

  <!-- Social Engineering: credential POST to GoPhish -->
  <rule id="100006" level="11">
    <if_sid>31103</if_sid>
    <url>/login</url>
    <match>POST</match>
    <description>Social Engineering: credential submission detected on phishing page</description>
    <mitre>
      <id>T1566.002</id>
    </mitre>
    <group>phishing,high_priority,</group>
  </rule>

</group>
```

---

### 4.3 Wazuh Active Response Configuration (VM1)

```xml
<!-- /var/ossec/etc/ossec.conf on VM1 — active response block -->
<ossec_config>

  <!-- Define the block script -->
  <command>
    <name>firewall-drop</name>
    <executable>firewall-drop</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>

  <!-- Auto-block on DDoS rules — HOTL autonomous tier -->
  <!-- rule_id 100001, 100002 = DDoS → auto block, no human needed -->
  <active-response>
    <command>firewall-drop</command>
    <location>defined-agent</location>
    <agent_id>001</agent_id>
    <!-- 001 = VM2 agent ID -->
    <rules_id>100001,100002</rules_id>
    <timeout>300</timeout>
    <!-- Block for 300 seconds, then auto-lift -->
  </active-response>

  <!-- Critical rules → do NOT auto-respond, escalate to Shuffle for human gate -->
  <!-- rules 100003, 100004 (malware) → handled by Shuffle workflow only -->

</ossec_config>
```

---

### 4.4 Wazuh-to-AI Integration Script (VM1)

```python
# /opt/ai_service/wazuh_ai_bridge.py
# Wazuh calls this via custom integration hook after each alert
# Mechanism: Wazuh integration → script → POST to Flask AI API
#            → receives prediction → updates alert via Wazuh API

import json
import sys
import requests

# ── Constants ──────────────────────────────────────────────────
AI_ENDPOINT   = "http://127.0.0.1:5000/predict"
WAZUH_API_URL = "https://127.0.0.1:55000"
WAZUH_USER    = "wazuh-wui"
WAZUH_PASS    = "your_api_password"

def extract_features(alert: dict) -> dict:
    # Extract flat feature dict from Wazuh alert JSON
    return {
        "rule_level"    : alert.get("rule", {}).get("level", 0),
        "rule_id"       : int(alert.get("rule", {}).get("id", 0)),
        "src_ip"        : alert.get("data", {}).get("srcip", "0.0.0.0"),
        "dst_port"      : int(alert.get("data", {}).get("dstport", 0)),
        "protocol"      : alert.get("data", {}).get("protocol", "unknown"),
        "hour_of_day"   : int(alert.get("timestamp", "T00")[11:13]),
        "groups"        : ",".join(alert.get("rule", {}).get("groups", [])),
    }

def main():
    # Wazuh passes alert JSON as file path in argv[1]
    alert_file = sys.argv[1]
    with open(alert_file) as f:
        alert = json.load(f)

    features = extract_features(alert)

    # POST to local AI Flask service
    try:
        response = requests.post(AI_ENDPOINT, json=features, timeout=2)
        prediction = response.json()
        # prediction = {"label": "anomaly", "score": 0.87, "action": "escalate"}
    except Exception as e:
        # AI service down → fail open, do not suppress alert
        prediction = {"label": "unknown", "score": 1.0, "action": "escalate"}

    # Tag alert with AI result via Wazuh API
    alert_id = alert.get("id")
    tag      = f"AI_{prediction['action'].upper()}"
    score    = prediction["score"]

    # Wazuh API: add comment/tag to alert
    auth = requests.auth.HTTPBasicAuth(WAZUH_USER, WAZUH_PASS)
    requests.put(
        f"{WAZUH_API_URL}/alerts/{alert_id}",
        json={"comment": f"{tag} score={score:.2f}"},
        auth=auth,
        verify=False,
        timeout=3
    )

    # If escalate → trigger Shuffle webhook
    if prediction["action"] == "escalate":
        requests.post(
            "http://127.0.0.1:5001/webhook/<SHUFFLE_HOOK_ID>",
            json={**alert, "ai_score": score, "ai_action": tag},
            timeout=3
        )

if __name__ == "__main__":
    main()
```

```xml
<!-- Register bridge script as Wazuh integration in ossec.conf on VM1 -->
<integration>
  <name>custom-ai-bridge</name>
  <hook_url>http://127.0.0.1:5000/predict</hook_url>
  <level>3</level>
  <!-- Only process alerts level 3+ to reduce noise on AI service -->
  <alert_format>json</alert_format>
</integration>
```

---

## Item 5: AI Pipeline Detail

### 5.1 Feature Engineering

```python
# /opt/ai_service/features.py
# Defines ALL features fed into Isolation Forest
# Must be identical between training (Colab) and inference (VM1 Flask)

import pandas as pd
import numpy as np
from collections import defaultdict

# Rolling frequency counter — tracks alert rate per src_ip per minute
_freq_window = defaultdict(list)

def compute_features(alert_dict: dict, history: list) -> np.ndarray:
    """
    Input:  raw alert dict from Wazuh + recent alert history list
    Output: 1D numpy array of features for model.predict()
    """

    rule_level   = int(alert_dict.get("rule_level", 0))
    rule_id      = int(alert_dict.get("rule_id", 0))
    src_ip       = alert_dict.get("src_ip", "0.0.0.0")
    dst_port     = int(alert_dict.get("dst_port", 0))
    hour_of_day  = int(alert_dict.get("hour_of_day", 0))
    protocol     = alert_dict.get("protocol", "unknown")

    # Feature 1: rule_level (direct ordinal)
    f_rule_level = rule_level

    # Feature 2: alert frequency — same src_ip in last 60 seconds
    recent_ips   = [a["src_ip"] for a in history[-100:]]
    f_ip_freq    = recent_ips.count(src_ip)

    # Feature 3: src_ip entropy — distributed attack vs single source
    # High entropy = many different IPs = distributed DDoS pattern
    from collections import Counter
    ip_counts    = Counter(recent_ips)
    total        = sum(ip_counts.values()) or 1
    f_ip_entropy = -sum((c/total)*np.log2(c/total) for c in ip_counts.values())

    # Feature 4: destination port risk score
    # Known high-risk ports scored higher
    port_risk    = {22: 0.8, 21: 0.7, 80: 0.4, 443: 0.3, 3306: 0.9}
    f_port_risk  = port_risk.get(dst_port, 0.5)

    # Feature 5: hour of day — attacks more anomalous during off-hours
    f_off_hours  = 1 if (hour_of_day < 6 or hour_of_day > 22) else 0

    # Feature 6: protocol encoding
    proto_map    = {"tcp": 0, "udp": 1, "icmp": 2, "unknown": 3}
    f_protocol   = proto_map.get(protocol.lower(), 3)

    # Feature 7: rule_id group risk
    # 100001-100002=DDoS(3), 100003-100004=malware(4), 100005-100006=phishing(2)
    if   rule_id in range(100001, 100003): f_rule_group = 3
    elif rule_id in range(100003, 100005): f_rule_group = 4
    elif rule_id in range(100005, 100007): f_rule_group = 2
    else:                                  f_rule_group = 1

    return np.array([
        f_rule_level,   # 0
        f_ip_freq,      # 1
        f_ip_entropy,   # 2
        f_port_risk,    # 3
        f_off_hours,    # 4
        f_protocol,     # 5
        f_rule_group,   # 6
    ], dtype=np.float32)
```

---

### 5.2 Training Script (Runs on Colab/Local)

```python
# train.py — execute on Colab or local machine, NOT on VM1
import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from features import compute_features

# ── Load exported Wazuh alerts ──────────────────────────────────
df = pd.read_csv("labeled_alerts.csv")
# Expected columns: rule_level, rule_id, src_ip, dst_port,
#                   hour_of_day, protocol, label (0=normal, 1=attack)

# ── Build feature matrix ────────────────────────────────────────
history = df.to_dict("records")
X = np.array([
    compute_features(row, history[:i])
    for i, row in enumerate(history)
])
y = df["label"].values  # 0 = normal/FP, 1 = true positive

# ── Model 1: Isolation Forest (unsupervised) ────────────────────
# Train ONLY on normal samples — learns baseline of normal behavior
X_normal = X[y == 0]
iso_forest = IsolationForest(
    n_estimators=100,
    contamination=0.05,   # assume 5% of normal data is noisy
    random_state=42
)
iso_forest.fit(X_normal)

# Predict on full dataset (-1=anomaly, 1=normal) → remap to (1, 0)
iso_preds = (iso_forest.predict(X) == -1).astype(int)

print("=== Isolation Forest ===")
print(classification_report(y, iso_preds,
      target_names=["Normal/FP", "Attack/TP"]))
print(confusion_matrix(y, iso_preds))

# ── Model 2: Random Forest (supervised, benchmark only) ─────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
rf = RandomForestClassifier(n_estimators=100, random_state=42)
rf.fit(X_train, y_train)
rf_preds = rf.predict(X_test)

print("=== Random Forest (benchmark) ===")
print(classification_report(y_test, rf_preds,
      target_names=["Normal/FP", "Attack/TP"]))
print(confusion_matrix(y_test, rf_preds))

# ── Serialize winner (Isolation Forest — no label dependency) ───
joblib.dump(iso_forest, "models/isolation_forest_v1.pkl")
joblib.dump(rf,         "models/random_forest_benchmark.pkl")
print("Models saved to /models/")
```

---

### 5.3 Inference Service (Runs on VM1)

```python
# /opt/ai_service/app.py — Flask inference API on VM1
import joblib
import numpy as np
from flask import Flask, request, jsonify
from features import compute_features

app = Flask(__name__)

# Load model once at startup — stays in RAM (~150MB)
MODEL_PATH = "/opt/ai_service/models/isolation_forest_v1.pkl"
model      = joblib.load(MODEL_PATH)

# Rolling alert history for frequency features
alert_history = []
MAX_HISTORY   = 200  # keep last 200 alerts in memory

@app.route("/predict", methods=["POST"])
def predict():
    alert = request.get_json()

    # Maintain rolling history for frequency features
    alert_history.append(alert)
    if len(alert_history) > MAX_HISTORY:
        alert_history.pop(0)

    features = compute_features(alert, alert_history)
    features_2d = features.reshape(1, -1)

    # Isolation Forest: -1 = anomaly, 1 = normal
    raw_pred = model.predict(features_2d)[0]
    score    = -model.score_samples(features_2d)[0]
    # score range: higher = more anomalous (remapped to 0.0–1.0 approx)
    score_normalized = float(np.clip(score / 0.5, 0.0, 1.0))

    # ── HOTL decision logic ─────────────────────────────────────
    rule_level = int(alert.get("rule_level", 0))

    if score_normalized < 0.3 and rule_level < 8:
        # Trivial/repetitive → AI suppresses autonomously
        action = "suppress"
    elif score_normalized >= 0.7 or rule_level >= 12:
        # High confidence anomaly or critical rule → escalate
        action = "escalate"
    else:
        # Uncertain → queue for human review
        action = "review"

    return jsonify({
        "label" : "anomaly" if raw_pred == -1 else "normal",
        "score" : round(score_normalized, 4),
        "action": action
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model": MODEL_PATH})

if __name__ == "__main__":
    # Bind to localhost only — not exposed externally
    app.run(host="127.0.0.1", port=5000, debug=False)
```

```bash
# Systemd service — keeps Flask alive on VM1 reboot
# /etc/systemd/system/ai-inference.service

[Unit]
Description=SOC AI Inference Service
After=network.target

[Service]
User=azureuser
WorkingDirectory=/opt/ai_service
ExecStart=/usr/bin/python3 /opt/ai_service/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
# Deploy commands on VM1
sudo systemctl daemon-reload
sudo systemctl enable ai-inference
sudo systemctl start ai-inference
sudo systemctl status ai-inference
```

---

## Item 6: Shuffle SOAR Workflow Plan

### 6.1 What Shuffle Does in This System

Shuffle sits on VM1 and acts as the automated response brain. Its job is to receive escalated alerts from Wazuh, decide what action to take based on the alert type, and either execute that action autonomously or hold it for human approval.

---

### 6.2 Shuffle Workflow Triggers

Three distinct workflows need to be built inside Shuffle:

---

**Workflow 1: DDoS Response (Autonomous — HOTL trivial)**

```
Trigger:    Wazuh fires rule 100001 or 100002 (DDoS rules)
            + AI returns action = "escalate"
                    ↓
Shuffle receives webhook with alert payload
                    ↓
Shuffle reads src_ip from alert
                    ↓
Shuffle SSHes into VM2 → adds iptables DROP rule for src_ip
                    ↓
Shuffle logs action to its audit trail
                    ↓
Shuffle updates Wazuh alert tag → "SOAR_BLOCKED"
                    ↓
Block auto-lifts after 5 minutes (timeout configured in Wazuh active response)
```

No human confirmation needed. This is the trivial/repetitive tier.

---

**Workflow 2: Malware Response (Human gate — HOTL privileged)**

```
Trigger:    Wazuh fires rule 100003 or 100004 (malware rules)
            + AI returns action = "escalate"
                    ↓
Shuffle receives webhook with alert payload
                    ↓
Shuffle sends notification to SOC analyst
(email or Slack message with alert details + AI score)
                    ↓
Notification contains two buttons: CONFIRM or DISMISS
                    ↓
Human reviews → clicks CONFIRM
                    ↓
Shuffle SSHes into VM2 → isolates affected process or kills connection
Shuffle updates Wazuh alert tag → "SOAR_CONTAINED"
                    ↓
         OR human clicks DISMISS
                    ↓
Shuffle logs dismissal → tags alert "SOAR_DISMISSED"
No action taken on VM2
```

Human confirmation required because process termination and host isolation are destructive/irreversible.

---

**Workflow 3: Social Engineering Response (Human gate — HOTL privileged)**

```
Trigger:    Wazuh fires rule 100005 or 100006 (phishing rules)
            + AI returns action = "escalate"
                    ↓
Shuffle receives webhook
                    ↓
Shuffle sends notification to SOC analyst
(includes: phishing URL hit, credential POST detected, timestamp, src_ip)
                    ↓
Human reviews → determines if simulated or real
                    ↓
CONFIRM → Shuffle logs confirmed phishing event
          Tags alert "SOAR_PHISHING_CONFIRMED"
          (no automated VM action needed for this scenario)
                    ↓
DISMISS → Tags alert "SOAR_FALSE_POSITIVE"
```

---

### 6.3 Shuffle Configuration Checklist (Non-Technical)

- Install Shuffle on VM1 via Docker Compose
- Create one webhook per workflow (3 webhooks total)
- Configure Wazuh integration to call correct webhook per rule group
- Set up SSH credential in Shuffle for VM2 access (used in Workflow 1 and 2)
- Configure notification channel (email is simplest for student project)
- Test each workflow end-to-end before running live attack simulations

---

## Item 7: Attack Simulation Plan

### 7.1 Attack Schedule

Run attacks in isolated sessions. Do not run multiple attack types simultaneously — this makes Wazuh alert data cleaner for AI training and easier to label afterward.

```
Session 1: Baseline (no attack)
→ Run system normally for 30–60 minutes
→ Collect normal alert data → this becomes your "normal" training dataset

Session 2: DDoS simulation
→ Execute HTTP flood + SYN flood from local Kali WSL2 → VM2 public IP
→ Run for 10–15 minutes
→ Observe Wazuh alerts firing, Shuffle auto-blocking

Session 3: Malware simulation
→ Execute SSH brute force + payload drop via Metasploit from local Kali
→ Run for 10–15 minutes
→ Observe Wazuh FIM alerts, Shuffle human gate triggering

Session 4: Social Engineering simulation
→ Send simulated phishing email via GoPhish
→ Team member clicks link from a browser on local machine
→ Observe GoPhish tracker hit + credential POST logged in Apache
→ Wazuh picks up Apache log entries

Session 5: Mixed (validation)
→ Run all three attack types in sequence
→ Validate that AI correctly classifies and routes each
→ Validate Shuffle executes correct workflow per attack type
```

---

### 7.2 Tools Per Attack (Local Kali WSL2)

|Attack|Tool|Target on VM2|
|---|---|---|
|HTTP flood|hping3 or slowloris|Port 80 (Apache)|
|SYN flood|hping3|Port 22 or 80|
|SSH brute force|Hydra|Port 22 (OpenSSH)|
|Payload delivery|Metasploit + msfvenom|Port 21 or 80|
|Phishing delivery|GoPhish (running on VM2)|Port 3333|
|Phishing interaction|Browser / curl on local machine|GoPhish campaign URL|

---

### 7.3 Data Labeling After Simulations

After all attack sessions, export Wazuh alerts as CSV. Label them based on timestamps:

- Alerts during Session 1 (baseline) → label 0 (normal)
- Alerts during Sessions 2–4 (attack windows) → label 1 (attack)
- Export this labeled CSV → use for AI training on Colab

---

## Item 8: SOC Tier Mapping Summary

|SOC Tier|Role in This Project|Implemented By|
|---|---|---|
|Tier 1: System Security|Continuous log collection and normalization|Wazuh Agent on VM2|
|Tier 1–2: Alert Management|Alert correlation + false alarm filtering|Wazuh rules + AI Isolation Forest|
|Tier 2–3: Threat Management|Threat classification + escalation routing|AI scoring + HOTL decision logic|
|Tier 3–4: Response & Recovery|Automated block + human-confirmed containment|Shuffle SOAR Workflows 1, 2, 3|

---

## Item 9: Configuration Checklist (Team Coordination View)

### VM1 Setup Tasks

- Install Wazuh Manager + Indexer + Dashboard (single-node deployment)
- Cap OpenSearch heap to 512MB in JVM options
- Install Docker + Docker Compose → deploy Shuffle
- Deploy AI Flask inference service as a background system service
- Register Wazuh-to-AI bridge integration in Wazuh config
- Register three Shuffle webhooks in Wazuh integration config
- Open firewall ports: 443 (dashboard), 1514/1515 (agent), 5001 (Shuffle internal)

### VM2 Setup Tasks

- Install Wazuh Agent → point to VM1 private IP
- Install and configure Apache2, OpenSSH, Vsftpd, GoPhish
- Configure Wazuh Agent to monitor all relevant log paths
- Open Azure NSG ports: 80, 21, 22, 3333 for attack surface
- Configure active response receiver for Shuffle block commands

### Local Machine Setup Tasks

- Install Kali WSL2 on Windows
- Install hping3, Hydra, Metasploit, slowloris, curl
- Note your public IP before each attack session (Azure NSG may need updating)
- Verify connectivity to VM2 public IP before each simulation

### AI Tasks

- Run baseline + attack sessions → export labeled alert CSV from Wazuh
- Train Isolation Forest + Random Forest on Colab
- Evaluate both models → record F1, precision, recall, false positive rate
- Serialize winning model → push to GitHub → pull onto VM1
- Verify inference service is running and responding on VM1

---

## Item 10: GitHub Repository Structure

```
banaspati/
├── README.md                   ← architecture overview + setup instructions
├── docs/
│   ├── architecture-diagram.png
│   ├── network-topology.png
│   └── final-report.pdf
├── wazuh/
│   ├── ossec-manager.conf      ← VM1 Wazuh config
│   ├── ossec-agent.conf        ← VM2 Wazuh config
│   └── local_rules.xml         ← custom detection rules
├── shuffle/
│   └── workflows/
│       ├── ddos-response.json
│       ├── malware-response.json
│       └── phishing-response.json
├── ai/
│   ├── train.py                ← training script (runs on Colab)
│   ├── features.py             ← feature engineering (shared)
│   ├── app.py                  ← Flask inference service
│   ├── models/
│   │   └── isolation_forest_v1.pkl
│   └── datasets/
│       └── labeled_alerts.csv
└── attack-simulation/
    ├── ddos-commands.md
    ├── malware-steps.md
    └── phishing-setup.md
```

---

## Team Task Division Suggestion (6–8 people)

|Role|Responsibility|Items Covered|
|---|---|---|
|Infrastructure Lead (1)|Azure VM setup, NSG rules, networking|Items 1, 2, 9|
|Wazuh Engineer (1–2)|Wazuh manager + agent config, custom rules|Items 4.1, 4.2, 4.3|
|AI Engineer (1–2)|Feature engineering, training, inference service|Item 5|
|SOAR Engineer (1)|Shuffle workflow design and testing|Item 6|
|Attack Simulation Lead (1)|Attack execution, data collection, labeling|Item 7|
|Documentation Lead (1)|Report writing, diagrams, GitHub repo structure|Item 10|

---


