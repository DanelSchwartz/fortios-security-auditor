# FortiOS Security & Hardening Auditor

A clean, minimalist, open-source Chrome Extension (Manifest V3) designed for professional security engineering, CIS benchmark compliance auditing, and runtime operational diagnostics of Fortinet FortiGate firewalls and FortiAnalyzer appliances.

Built for SecOps engineers and MSSPs who require a high-density, utility-focused interface with zero external dependencies, zero CDNs, and strict client-side execution.

---

## Key Features

- **Dual-Engine Architecture**:
  - **Engine 1 (Runtime CLI)**: Parses live terminal diagnostic outputs (`get system status`, `diagnose hardware sysinfo conserve`, `get vpn ipsec tunnel summary`, etc.).
  - **Engine 2 (Static Config AST)**: Tokenizes and validates `.conf` / `.cfg` backup files using a multi-VDOM context stack and entity resolution graph.
- **Comprehensive Security Scope (50+ Checks)**:
  - **CIS Benchmarks (FortiOS 7.x)**: Admin idle timeout, account lockout, non-standard admin ports, NTP synchronization, global password policy complexity, legacy SNMPv1/v2c removal, centralized logging, and factory default certificate replacement.
  - **Threat-Informed Defense & CVE Mitigations**: Detection logic for critical attack vectors including SSL-VPN Web Mode exposure (CVE-2023-27997, CVE-2024-21762), FGFM protocol perimeter exposure (CVE-2024-23113, CVE-2024-47575), and firmware lifecycle patch tracking.
  - **Operational & Network Diagnostics**: WAD proxy memory leak/freeze detection, HA split-brain and failover flapping forensics, FortiGuard Anycast rating latency, BGP route churn, FortiAnalyzer storage RAID health, and silent log forwarder detection.
- **Built-in Diagnostic Cheat Sheet**: Includes a verified 1-click command bundle tab to instantly extract the exact telemetry needed for full operational health checks without manually typing syntax.
- **Privacy & Compliance**: 
  - 100% client-side execution.
  - Zero external trackers, analytics, or remote CDN script loads (fully CSP compliant with Manifest V3).
- **Executive Reporting & Exports**:
  - Instantly export audit deliverables to standalone styled HTML reports with interactive remediation CLI blocks.
  - One-click clean plain-text copy optimized for ticketing systems like Jira and ClickUp (zero raw markdown artifacts).

---

## Installation (Developer Mode)

1. Clone or download this repository as a ZIP archive and extract it locally.
2. Open Google Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode** using the toggle switch in the top-right corner.
4. Click **Load unpacked** in the top-left corner.
5. Select the `fortios-security-auditor` directory.

---

## Usage Workflow

For a comprehensive audit, it is highly recommended to provide **both** the static configuration and the live CLI telemetry.

1. **Get the Commands:** Open the extension and switch to the **Diagnostic CLI Cheat Sheet** tab. Click **Copy Verified 1-Click Bundle** for either FortiGate or FortiAnalyzer.
2. **Run & Save:** Paste the commands into your appliance's CLI via SSH/Console and save the complete terminal output to a `.txt` or `.log` file.
3. **Backup Config:** Download a full configuration backup (`.conf` or `.cfg`) directly from the appliance GUI.
4. **Analyze:** Switch back to the **Security Audit & Inspector** tab in the extension. Drag and drop **both** the configuration file and the CLI log file into the dropzone.
5. Click **Analyze Security** to execute the complete multi-engine audit suite.
6. Review findings categorized by severity (`CRITICAL`, `WARNING`, `PASS`, `INFO`) with exact target configuration paths and 1-click copyable remediation CLI commands.
7. Export reports as standalone HTML or clean ASCII plain text for documentation and ticketing.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
