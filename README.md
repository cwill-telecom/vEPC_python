#  LTE vEPC Python Implementation

This repository contains a Python implementation of the **Long-Term Evolution (LTE) Virtual Evolved Packet Core (EPC)** network components.

##  Overview

The **LTE vEPC Python Implementation** provides a virtualized sandbox for exploring LTE protocols without the need for expensive proprietary hardware. It includes full support for handover scenarios, integrated security modules, and real-time traffic monitoring.

---

##  Architecture

The system is divided into core functional entities and supporting infrastructure to mirror a real-world 3GPP deployment. 

```
EnB --S1-MME--> [PLMN 311228] --S1-MME--> M2M vMME --S11--> M2M vSGW1
                                                                 |  S5 (into MCC)
                                                                 v
                                        MCC (vSAEGW-1 vSGW + 2 vPGWs)
                                        ├── M2M vPGW1        --Gx--> vPCRF --SGi--> BV FW
                                        └── IoT/pLTE vPGW2   --Gx--> vPCRF --SGi--> BV FW
```

### Core Network Components
* **HSS (Home Subscriber Server):** Central database for subscriber data and authentication.
* **MME (M2M vMME):** Handles mobility management and session establishment; selects the vPGW anchor per UE based on APN.
* **SGW (M2M vSGW1):** Routes user data packets between eNodeB and whichever vPGW the MME selected.
* **PGW (M2M vPGW1 / IoT-pLTE vPGW2):** Two PGW instances of the same module, distinguished by role/APN; each provides connectivity to external IP networks (SGi towards the BV FW firewall) and pulls PCC rules from vPCRF over Gx.
* **PCRF (vPCRF):** Serves the Gx interface for both vPGWs, returning the PCC (QoS/charging) rule to apply per session.
* **RAN (Radio Access Network):** Simulates LTE base station (EnB) functionality.

### File Structure
```text
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── database_setup.sql           # MySQL schema
├── core/
│   ├── hss.py                   # Home Subscriber Server
│   ├── mme.py                   # M2M vMME - Mobility Management Entity
│   ├── sgw.py                   # M2M vSGW1 - Serving Gateway
│   ├── pgw.py                   # M2M vPGW1 / IoT-pLTE vPGW2 (role-selectable Packet Gateway)
│   ├── pcrf.py                  # vPCRF - Policy and Charging Rules Function (Gx server)
│   ├── pcrf_client.py           # Gx client used by pgw.py to reach vPCRF
│   ├── ran.py                   # Radio Access Network
│   └── sink.py                  # Traffic Sink
├── protocols/
│   ├── diameter.py              # Diameter protocol
│   ├── gtp.py                   # GTP protocol
│   └── s1ap.py                  # S1AP protocol
├── network/
│   ├── network.py               # Network utilities
│   ├── udp_client.py            # UDP client implementation
│   ├── udp_server.py            # UDP server implementation
│   ├── sctp_client.py           # SCTP client implementation
│   ├── sctp_server.py           # SCTP server implementation
│   └── tun.py                   # TUN/TAP interface
├── security/
│   └── security.py              # Encryption and integrity
├── utils/
│   ├── utils.py                 # Utility functions
│   ├── sync.py                  # Synchronization primitives
│   ├── mysql.py                 # MySQL client
│   └── telecom.py               # Telecom utilities
└── simulators/
    ├── ran_simulator.py         # Basic UE simulation
    └── ran_simulator_handover.py # Handover simulation
```

---

##  System Requirements & Setup

### Prerequisites
* **OS:** Linux/Unix environment (Required for **TUN/TAP** interfaces).
* **Database:** MySQL server for HSS storage.
* **Privileges:** **Root privileges** required for network interface configuration.
* **Hardware:** Multiple CPU cores recommended for multi-threaded operation.

### Installation
```bash
# Verify Python 3.8+
python3 --version

# Install dependencies
pip install mysql-connector-python pycryptodome
```

### Database Setup
```sql
CREATE DATABASE hss;
USE hss;

CREATE TABLE autn_info (
    imsi BIGINT PRIMARY KEY,
    key_id BIGINT,
    rand_num BIGINT
);

CREATE TABLE loc_info (
    imsi BIGINT PRIMARY KEY,
    mmei INT
);
```

---

##  Usage

### 1. Starting the EPC
Components should be started in the following order:

| Component | Command | Description |
| :--- | :--- | :--- |
| **HSS** | `python3 hss.py 4` | Start with 4 worker threads |
| **vPCRF** | `python3 pcrf.py 4` | Gx server for both vPGWs, 4 worker threads |
| **MME** | `python3 mme.py 8` | Start with 8 worker threads (M2M vMME, PLMN 311228) |
| **SGW** | `python3 sgw.py 4 4 4` | S11, S1, S5 thread counts (M2M vSGW1) |
| **PGW (M2M vPGW1)** | `python3 pgw.py 4 4 m2m` | S5, SGi thread counts; role defaults to `m2m` |
| **PGW (IoT/pLTE vPGW2)** | `python3 pgw.py 4 4 iot` | S5, SGi thread counts; second instance on IoT ports |
| **Sink** | `python3 sink.py 2` | Terminate traffic for testing |

Start `pcrf.py` before `pgw.py`, and start both `pgw.py` instances (M2M and IoT roles) before `mme.py`, since the MME picks a vPGW per-UE based on APN (`APN_M2M` -> vPGW1, `APN_IOT_PLTE` -> vPGW2).

### 2. Running Simulations
* **Basic UE Registration:**
  ```bash
  python3 ran_simulator.py 4 300  # 4 threads, 300 seconds
  ```
* **Handover Testing:**
  ```bash
  python3 ran_simulator_handover.py 1 300  # 1 thread, 300 seconds
  ```

### 3. Configuration
Edit the global variables at the top of each component file (e.g., `mme.py`):
```python
g_mme_ip_addr = "10.129.26.169"
g_mme_port = 5000
g_hss_ip_addr = "10.129.26.169"
g_hss_port = 6000
```

---

##  Protocol Implementation Details

### Message Types & Headers

| Protocol | Header Size | Key Message Types |
| :--- | :--- | :--- |
| **Diameter** | 3 Bytes | 1: Auth Info Request (S6a), 2: Location Update (S6a), 3: Gx CCR, 4: Gx CCA |
| **GTP** | 13 Bytes | 1: Create Session, 2: Modify Bearer, 4: Indirect Tunnel |
| **S1AP** | 11 Bytes | 1: Initial Attach, 3: Security Mode, 7-10: Handover |

### Handover Procedure
The implementation supports **intra-MME handover** following this sequence:
1. **Handover Initiation:** RAN → MME
2. **Target RAN Preparation:** MME → Target RAN
3. **Indirect Tunnel Setup:** MME ↔ SGW
4. **Data Forwarding:** Source RAN → Target RAN via SGW
5. **Path Switch:** Target RAN → MME
6. **Resource Cleanup:** MME → SGW

[Image of LTE handover procedure]

### Security Features
* **Encryption:** AES-256 (NAS messages).
* **Integrity:** HMAC-SHA256 coverage for all NAS messages.
* **Key Management:** Separate derivation for encryption and integrity keys based on UE authentication.

---

##  Performance & Troubleshooting

### Considerations
* **Memory:** UE Context (~200 bytes), Packet Buffers (1KB), Thread Overhead (~8MB).
* **Network:** <10ms latency recommended for realistic simulation.

### Common Fixes
* **MySQL connection failed:** `sudo systemctl status mysql`
* **Permission Denied (TUN):** Use `sudo` or add user to `netdev` group.
* **Port in use:** `netstat -tulpn | grep :5000`

### Debugging
Enable detailed logs via environment variables:
```bash
export DEBUG=1
export TRACE=1
python3 mme.py 4
```

---

##  Testing
* **Unit Tests:** `python3 -m pytest tests/`
* **Integration:** `python3 tests/test_attach.py`
* **Benchmarks:** `python3 tests/benchmark_throughput.py`

---

##  License & References
* **License:** MIT License.
* **Standards:** 3GPP TS 24.301 (NAS), TS 36.413 (S1AP), TS 29.274 (GTPv2), TS 29.212 (Diameter).
