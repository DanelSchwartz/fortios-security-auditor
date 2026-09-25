/**
 * SecOps Health Check & Config Analyzer (Manifest V3)
 * Dual-Engine Parser & Hardening Auditor for FortiGate Firewalls & FortiAnalyzer
 *
 * Engine 1: Runtime CLI Engine (Live diagnostic outputs)
 * Engine 2: FortiOS Configuration File (.conf / .cfg) Tokenizer & Parser
 * Deduplication Engine: Keyed by Check ID with multi-file aggregation
 * Clean Clipboard Exporter: Rich Text (text/html) & Plain Text (no raw markdown **)
 */

// ---------------------------------------------------------------------
// Checklist Thresholds & Severities
// ---------------------------------------------------------------------
const THRESHOLDS = {
  fgtUptimeWarnHours: 24,
  fgtCpuFail: 80,
  fgtCpuWarn: 60,
  fgtMemFail: 80,
  fgtMemWarn: 70,
  fdnStaleHours: 24,
  sdwanLatencyWarnMs: 50,
  fazStorageFail: 75,
  fazStorageWarn: 70,
  fazCpuFail: 80,
  fazMemFail: 85,
  fazIdleWarnSeconds: 60,
};

const SEVERITY_RANK = {
  ERROR: 5,
  FAIL: 4,
  WARN: 3,
  PASS: 2,
  INFO: 1,
  NOT_EVALUATED: 1,
};

const CIS_BENCHMARK_TOTAL_CONTROLS = 11;
const CIS_BENCHMARK_CONTROL_IDS = [
  "CIS-ADM-01",
  "CIS-ADM-02",
  "CIS-ADM-03",
  "CIS-SYS-01",
  "CIS-SYS-02",
  "CIS-AUTH-01",
  "CIS-MGMT-01",
  "CIS-LOG-01",
  "CIS-AUTH-02",
  "CIS-TLS-01",
  "CIS-CERT-01",
];

const CONFIGURABLE_HIGH_RISK_COUNTRIES = {
  TR: "Turkey",
  TUR: "Turkey",
  RU: "Russia",
  RUS: "Russia",
  CN: "China",
  CHN: "China",
  IR: "Iran",
  IRN: "Iran",
  AE: "UAE",
  ARE: "UAE",
  UAE: "UAE",
  IN: "India",
  IND: "India",
  TH: "Thailand",
  THA: "Thailand",
  RS: "Serbia",
  SRB: "Serbia",
  GE: "Georgia",
  GEO: "Georgia",
  ME: "Montenegro",
  MNE: "Montenegro",
  UA: "Ukraine",
  UKR: "Ukraine",
  BY: "Belarus",
  BLR: "Belarus",
  KP: "North Korea",
  PRK: "North Korea",
  SY: "Syria",
  SYR: "Syria",
  BR: "Brazil",
  BRA: "Brazil",
  VN: "Vietnam",
  VNM: "Vietnam",
  ID: "Indonesia",
  IDN: "Indonesia",
  PK: "Pakistan",
  PAK: "Pakistan",
  EG: "Egypt",
  EGY: "Egypt",
  SA: "Saudi Arabia",
  SAU: "Saudi Arabia",
  QA: "Qatar",
  QAT: "Qatar",
  JO: "Jordan",
  JOR: "Jordan",
  LB: "Lebanon",
  LBN: "Lebanon",
  IQ: "Iraq",
  IRQ: "Iraq",
  YE: "Yemen",
  YEM: "Yemen",
  AF: "Afghanistan",
  AFG: "Afghanistan",
  ZA: "South Africa",
  ZAF: "South Africa",
  NG: "Nigeria",
  NGA: "Nigeria",
  CO: "Colombia",
  COL: "Colombia",
  MX: "Mexico",
  MEX: "Mexico",
};

function formatCountry(code) {
  return CONFIGURABLE_HIGH_RISK_COUNTRIES[code] ? `${CONFIGURABLE_HIGH_RISK_COUNTRIES[code]} (${code})` : code;
}

function redactSensitiveData(text) {
  if (!text || typeof text !== "string") return text;
  return text
    .replace(/(set\s+(?:passwd|password|psksecret|private-key|secret|auth-password|priv-password)\s+ENC\s+)\S+/gi, "$1[REDACTED_SECRET]")
    .replace(/(set\s+(?:passwd|password|psksecret|private-key|secret)\s+)(?!"(?:\[REDACTED_SECRET\]|\s*")|\[REDACTED_SECRET\])(?:"[^"]*"|\S+)/gi, "$1[REDACTED_SECRET]");
}

function normalizeApplianceName(rawName, fallback = "Primary-FW") {
  if (!rawName || typeof rawName !== "string") {
    return (fallback !== undefined && fallback !== "default" && fallback !== ":") ? fallback : "Primary-FW";
  }
  let clean = rawName.trim().replace(/^["'\s:=]+|["'\s:=]+$/g, "").trim();
  clean = clean.replace(/^[:\s]+|[:\s]+$/g, "").trim();

  if (!clean || clean === ":" || clean === "::" || clean.toLowerCase() === "default") {
    return (fallback !== undefined && fallback !== "default" && fallback !== ":") ? fallback : "Primary-FW";
  }

  const m = /\b(?:FGT-[A-Za-z0-9_-]+|[A-Z0-9]+(?:-[A-Z0-9]+)*)\b/i.exec(clean);
  if (m && m[0]) {
    return m[0];
  }

  return clean || ((fallback !== undefined && fallback !== "default" && fallback !== ":") ? fallback : "Primary-FW");
}

function extractDeviceIdentity(text, defaultName = "Primary-FW") {
  const fallback = normalizeApplianceName(defaultName, "Primary-FW");
  if (!text) return fallback;

  // 1. Live/event logs or syslog tags: appliance=servername, devname=servername, device=servername
  const logMatches = [...text.matchAll(/(?:^|\s|,|;)(?:appliance|devname|device|dname)\s*[:=]\s*["']?([^"'\r\n\s,;]+)["']?/gi)];
  for (const lm of logMatches) {
    const norm = normalizeApplianceName(lm[1], "");
    if (norm && norm !== ":" && norm !== "Primary-FW") return norm;
  }

  // 2. Configuration file: set hostname or hostname
  const hostConfMatches = [...text.matchAll(/(?:set\s+hostname|hostname)\s+["']?([^"'\r\n\s]+)["']?/gi)];
  for (const hm of hostConfMatches) {
    const norm = normalizeApplianceName(hm[1], "");
    if (norm && norm !== ":" && !/^(?:FortiGate|FortiGate-\w+)$/i.test(norm)) return norm;
    if (norm && norm !== ":") return norm;
  }

  // 3. CLI status: Hostname: servername or Appliance: servername
  const hostCliMatches = [...text.matchAll(/(?:^|\n)\s*(?:Hostname|Appliance)\s*:\s*([^\r\n\s]+)/gi)];
  for (const cm of hostCliMatches) {
    const norm = normalizeApplianceName(cm[1], "");
    if (norm && norm !== ":") return norm;
  }

  // 4. Serial number
  const serialMatches = [...text.matchAll(/(?:Serial-Number|serial)\s*[:=]\s*([A-Za-z0-9_-]+)/gi)];
  for (const sm of serialMatches) {
    const norm = normalizeApplianceName(sm[1], "");
    if (norm && norm !== ":") return norm;
  }

  return fallback;
}

const DIAGNOSTIC_COMMANDS = {
  "CIS-MED-01": "show system global | grep -i banner",
  "CIS-HIGH-01": "show system auto-install",
  "SEC-HIGH-02": "show system settings | grep -i src-check",
  "CIS-MED-02": "show system dns",
  "SEC-HIGH-01": "show system admin",
  "SEC-MED-01": "show firewall ssl-ssh-profile",
  "SEC-CRIT-01": "show system interface | grep -i fgfm",
  "SEC-CRIT-02": "show vpn ssl web portal",
  "SEC-CRIT-03": "get system status",
  "SEC-LIFE-01": "get system status",
  "OPS-HIGH-01": "diagnose test application wad 1000",
  "OPS-MEM-01": "diagnose test application wad 1000",
  "OPS-HIGH-02": "diagnose sys ha history read",
  "OPS-HA-01": "diagnose sys ha history read",
  "OPS-MED-01": "diagnose debug rating",
  "OPS-DNS-01": "diagnose debug rating",
  "OPS-MED-02": "get router info bgp dampening flap-statistics",
  "OPS-BGP-01": "get router info bgp dampening flap-statistics",
  "FAZ-HIGH-01": "diagnose fortilogd lograte-device",
  "FAZ-FWD-01": "diagnose fortilogd lograte-device",
  "FAZ-CRIT-01": "diagnose system raid status",
  "FAZ-DISK-01": "diagnose system raid status",
  "FGT-SYS-01": "get system status",
  "FGT-PERF-01": "get system performance status",
  "FGT-MEM-02": "diagnose hardware sysinfo conserve",
  "FGT-SESS-01": "diagnose sys session stat",
  "FGT-RT-BGP-01": "get router info bgp summary",
  "FGT-RT-OSPF-01": "get router info ospf neighbor",
  "FGT-HA-01": "get system ha status",
  "FGT-FG-01": "diagnose autoupdate status",
  "FGT-IPSEC-01": "get vpn ipsec tunnel summary",
  "FGT-SDWAN-01": "diagnose sys sdwan health-check",
  "FGT-FEED-01": "get system external-resource",
  "FGT-NET-01": "get system interface physical",
  "FGT-NET-02": "diagnose netlink interface list",
  "FGT-CERT-01": "get vpn certificate local details",
  "SEC-INTF-01": "show system interface",
  "SEC-USER-01": "show user local",
  "FGT-BAN-01": "diagnose user ban list",
  "FGT-LOG-01": "diagnose test application miglogd 6",
  "FGT-SYS-03": "diagnose debug crashlog read",
  "FAZ-STOR-01": "diagnose system print df",
  "FAZ-CONN-01": "diagnose test application oftpd 3",
  "FAZ-SYS-01": "get system performance",
  "FAZ-IDX-01": "diagnose fortilogd msgrate",
  "SEC-VIP-01": "show firewall vip",
  "SEC-VPN-01": "show vpn ssl settings",
  "SEC-FW-01": "show firewall policy",
  "SEC-FW-02": "show firewall policy",
  "CIS-ADM-01": "get system global",
  "CIS-ADM-02": "get system global",
  "CIS-ADM-03": "get system global",
  "CIS-SYS-01": "get system status",
  "CIS-SYS-02": "get system ntp",
  "CIS-AUTH-01": "show system password-policy",
  "CIS-MGMT-01": "show system snmp community",
  "CIS-LOG-01": "show log fortianalyzer setting",
  "CIS-AUTH-02": "show system admin",
  "CIS-TLS-01": "get system global | grep -i strong-crypto",
  "CIS-CERT-01": "get vpn certificate local details"
};

function makeFinding(optionsOrId, ...args) {
  let f;
  if (typeof optionsOrId === "object" && optionsOrId !== null) {
    const {
      id,
      altId,
      component,
      status = "INFO",
      category,
      source = "cli",
      deviceId = "Primary-FW",
      deviceName = "",
      diagnosticCmd = "",
      targetConfig = "",
      data = {},
      remediationCli = "",
      actionText = "",
      findingText = ""
    } = optionsOrId;

    const assignedDevId = normalizeApplianceName(
      optionsOrId.appliance || deviceId || deviceName,
      "Primary-FW"
    );

    const mappedAltId = altId || (
      id === "SEC-LIFE-01" ? "SEC-CRIT-03" :
      id === "SEC-CRIT-03" ? "SEC-LIFE-01" :
      id === "OPS-MEM-01" ? "OPS-HIGH-01" :
      id === "OPS-HIGH-01" ? "OPS-MEM-01" :
      id === "OPS-HA-01" ? "OPS-HIGH-02" :
      id === "OPS-HIGH-02" ? "OPS-HA-01" :
      id === "OPS-DNS-01" ? "OPS-MED-01" :
      id === "OPS-MED-01" ? "OPS-DNS-01" :
      id === "OPS-BGP-01" ? "OPS-MED-02" :
      id === "OPS-MED-02" ? "OPS-BGP-01" :
      id === "FAZ-FWD-01" ? "FAZ-HIGH-01" :
      id === "FAZ-HIGH-01" ? "FAZ-FWD-01" :
      id === "FAZ-DISK-01" ? "FAZ-CRIT-01" :
      id === "FAZ-CRIT-01" ? "FAZ-DISK-01" : ""
    );

    f = {
      id,
      altId: mappedAltId,
      component: component || id,
      status,
      category: category || (id.startsWith("CIS-") ? "CIS Benchmark" : (id.startsWith("SEC-") ? "Security & Hardening" : "SecOps Operational")),
      source,
      deviceId: assignedDevId,
      deviceName: assignedDevId,
      appliance: assignedDevId,
      diagnosticCmd: diagnosticCmd || DIAGNOSTIC_COMMANDS[id] || (mappedAltId ? DIAGNOSTIC_COMMANDS[mappedAltId] : "") || "",
      targetConfig: targetConfig || getFindingTargetConfig({ id }),
      data: data || {},
      remediationCli: remediationCli || "",
      actionText: actionText || "",
      findingText: findingText || ""
    };
  } else {
    const id = optionsOrId;
    const component = args[0] || id;
    const status = args[1] || "INFO";
    const findingText = args[2] || "";
    const actionText = args[3] || "";
    const source = args[4] || "cli";
    const targetConfig = args[5] || "";

    const mappedAltId = (
      id === "SEC-LIFE-01" ? "SEC-CRIT-03" :
      id === "SEC-CRIT-03" ? "SEC-LIFE-01" :
      id === "OPS-MEM-01" ? "OPS-HIGH-01" :
      id === "OPS-HIGH-01" ? "OPS-MEM-01" :
      id === "OPS-HA-01" ? "OPS-HIGH-02" :
      id === "OPS-HIGH-02" ? "OPS-HA-01" :
      id === "OPS-DNS-01" ? "OPS-MED-01" :
      id === "OPS-MED-01" ? "OPS-DNS-01" :
      id === "OPS-BGP-01" ? "OPS-MED-02" :
      id === "OPS-MED-02" ? "OPS-BGP-01" :
      id === "FAZ-FWD-01" ? "FAZ-HIGH-01" :
      id === "FAZ-HIGH-01" ? "FAZ-FWD-01" :
      id === "FAZ-DISK-01" ? "FAZ-CRIT-01" :
      id === "FAZ-CRIT-01" ? "FAZ-DISK-01" : ""
    );

    f = {
      id,
      altId: mappedAltId,
      component,
      status,
      category: id.startsWith("CIS-") ? "CIS Benchmark" : (id.startsWith("SEC-") ? "Security & Hardening" : "SecOps Operational"),
      source,
      deviceId: "Primary-FW",
      deviceName: "Primary-FW",
      appliance: "Primary-FW",
      diagnosticCmd: DIAGNOSTIC_COMMANDS[id] || (mappedAltId ? DIAGNOSTIC_COMMANDS[mappedAltId] : "") || "",
      targetConfig: targetConfig || getFindingTargetConfig({ id }),
      data: {},
      remediationCli: "",
      actionText: actionText || "",
      findingText: findingText || ""
    };
  }
  return f;
}

function renderFindingText(f, lang = "en") {
  const d = f.data || {};

  switch (f.id) {
    case "FGT-SYS-01":
      if (f.status === "PASS") {
        return `System uptime is normal: ${d.uptimeStr || ">24 hours"} (exceeds 24 hours). Continuous operation verified with no recent reboot.`;
      } else {
        return `System uptime is low: ${d.uptimeStr || "<24 hours"} (<24 hours). Indicates recent reboot, power-cycle event, or uncoordinated firmware upgrade.`;
      }

    case "FGT-PERF-01":
      if (f.status === "PASS") {
        return `Hardware performance is healthy: CPU ${d.cpu ?? 0}%, Memory ${d.mem ?? 0}% (within operational baseline limits).`;
      } else {
        return `Elevated resource utilization: CPU ${d.cpu ?? 0}%, Memory ${d.mem ?? 0}%. Exceeds operational capacity thresholds.`;
      }

    case "FGT-HA-01":
      if (f.status === "PASS") {
        return "HA cluster is operating normally: health status OK, all cluster members in-sync.";
      } else {
        return `HA cluster issue detected: ${d.detail || "Cluster health degraded or member synchronization out-of-sync"}.`;
      }

    case "FGT-FG-01":
      if (f.status === "PASS") {
        return "FortiGuard service synchronization is active and definitions are up-to-date.";
      } else {
        return `FortiGuard synchronization error: ${d.detail || "Definitions stale or communication unreachable"}.`;
      }

    case "FGT-IPSEC-01":
      if (f.status === "PASS") {
        return `All IPsec tunnels are operational: ${d.up ?? 0}/${d.total ?? 0} active.`;
      } else {
        return `IPsec tunnel degradation: ${d.down ?? 0} of ${d.total ?? 0} tunnels are down.`;
      }

    case "FGT-SDWAN-01":
      if (f.status === "PASS") {
        return "SD-WAN health check SLAs are compliant across all monitored member interfaces.";
      } else {
        return `SD-WAN SLA breach: ${d.detail || "Packet loss, latency, or jitter exceeds SLA target"}.`;
      }

    case "FGT-FEED-01":
      if (f.status === "PASS") {
        return "External threat feeds (threat-feed / external-resource) are actively updated and connected.";
      } else {
        return `Threat feed synchronization error: ${d.detail || "Feed unreachable or refresh failed"}.`;
      }

    case "SEC-INTF-01":
      if (f.status === "PASS") {
        return "Administrative management protocols (HTTP, Telnet) are disabled on external WAN interfaces.";
      } else {
        return `Insecure administrative access detected on WAN interface: ${d.intf || "WAN"}.`;
      }

    case "SEC-USER-01":
      if (f.status === "PASS") {
        return "Local administrative users enforce multi-factor authentication (two-factor enabled).";
      } else {
        return `Local user account lacks mandatory MFA: ${d.user || "Admin"}.`;
      }

    case "FGT-BAN-01":
      if (f.status === "PASS") {
        return "Active IP quarantine/ban list is empty or within baseline thresholds.";
      } else {
        return `Elevated quarantine activity: ${d.count ?? 0} IP addresses currently banned.`;
      }

    case "FGT-LOG-01":
      if (f.status === "PASS") {
        return "Logging daemon (miglogd) operates normally: zero log queue drops.";
      } else {
        return "Logging pipeline degraded: miglogd dropping logs due to buffer saturation.";
      }

    case "FGT-MEM-02":
      if (f.status === "PASS") {
        return "Memory conserve mode is inactive: system operates within standard thresholds.";
      } else {
        return "Critical: FortiGate is in memory conserve mode. UTM features may be bypassed.";
      }

    case "FGT-SESS-01":
      if (f.status === "PASS") {
        return `Stateful session table utilization is normal: ${d.active ?? 0} active sessions.`;
      } else {
        return `Session table capacity warning: ${d.active ?? 0} sessions active.`;
      }

    case "FGT-NET-01":
      if (f.status === "PASS") {
        return "All physical interfaces report Full Duplex and Gigabit speed negotiation.";
      } else {
        return `Physical link negotiation issue: ${d.detail || "Half-duplex or 100Mbps speed detected"}.`;
      }

    case "FGT-NET-02":
      if (f.status === "PASS") {
        return "Interface packet error and collision rates are within standard operational baselines (<0.01%).";
      } else {
        return `Elevated interface packet error ratio: ${d.intf || "Interface"} reports CRC errors.`;
      }

    case "FGT-CERT-01":
      if (f.status === "PASS") {
        return "Local VPN and SSL inspection certificates are valid and far from expiration.";
      } else {
        return `Local certificate expiration warning: ${d.cert || "Certificate"} expires soon.`;
      }

    case "FGT-RT-BGP-01":
      if (f.status === "PASS") {
        return "Dynamic BGP routing peer sessions are established and prefix exchanges are normal.";
      } else {
        return `BGP peer session down or flapping: ${d.peer || "Peer"} in ${d.state || "Idle"} state.`;
      }

    case "FGT-RT-OSPF-01":
      if (f.status === "PASS") {
        return "OSPF routing adjacencies are fully established (FULL state).";
      } else {
        return `OSPF neighbor issue: ${d.neighbor || "Neighbor"} in ${d.state || "Init"} state.`;
      }

    case "FGT-SYS-03":
      if (f.status === "PASS") {
        return "System crashlog is clean: zero daemon segfaults or kernel crashes recorded in last 30 days.";
      } else {
        return `Process crash detected in crashlog: ${d.daemon || "Application"} crashed with signal ${d.signal || "11"}.`;
      }

    case "FAZ-STOR-01":
      if (f.status === "PASS") {
        return `FortiAnalyzer storage utilization is optimal: ${d.usedPct ?? 0}% used.`;
      } else {
        return `FortiAnalyzer storage capacity alert: ${d.usedPct ?? 0}% allocated.`;
      }

    case "FAZ-CONN-01":
      if (f.status === "PASS") {
        return "All managed devices are actively communicating with FortiAnalyzer.";
      } else {
        return `Managed device connectivity issue: ${d.count ?? 0} device(s) offline.`;
      }

    case "FAZ-SYS-01":
      if (f.status === "PASS") {
        return "FortiAnalyzer CPU and memory metrics are within normal operating bounds.";
      } else {
        return "FortiAnalyzer system performance warning: high CPU or memory load.";
      }

    case "FAZ-IDX-01":
      if (f.status === "PASS") {
        return "Log indexing pipeline is healthy: log insertion rate is balanced.";
      } else {
        return "Log indexing latency detected: indexing queue backlogged.";
      }

    default:
      return f.findingText || `Control ${f.id}: Evaluation complete (Status: ${f.status}).`;
  }
}

function renderFindingAction(f, lang = "en") {
  return f.actionText || "";
}

function cleanVal(v) {
  if (!v) return "";
  return v.replace(/^"|"$/g, "").trim();
}

function extractQuotedTokens(str) {
  if (!str) return [];
  const tokens = [];
  const regex = /"([^"]+)"|(\S+)/g;
  let m;
  while ((m = regex.exec(str)) !== null) {
    const val = m[1] || m[2];
    if (val) tokens.push(val.replace(/^"+|"+$/g, "").trim());
  }
  return tokens;
}

function hasCommand(text, commandFragment) {
  const escaped = commandFragment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(escaped, "i").test(text);
}

function extractCommandOutput(text, commandPattern) {
  if (!text) return "";
  const cmdStr = typeof commandPattern === "string" 
    ? commandPattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
    : commandPattern.source;
  const cmdRegex = new RegExp(`(?:^|[#$]|\\n)\\s*${cmdStr}[^\\r\\n]*\\r?\\n([\\s\\S]*?)(?=(?:\\r?\\n[A-Za-z0-9_.-]+(?:\\s*\\([^)]+\\))?\\s*[#$]|\\n\\s*--More--|$))`, "i");
  const match = cmdRegex.exec(text);
  return match && match[1] ? match[1].trim() : "";
}

function isFazOutput(text) {
  return (
    /Platform Full Name\s*:\s*FortiAnalyzer/i.test(text) ||
    /FortiAnalyzer-VM/i.test(text) ||
    /\bFAZVM\d*\b/i.test(text) ||
    /diagnose dvm device list/i.test(text) ||
    /diagnose log device/i.test(text) ||
    /diagnose test application oftpd/i.test(text) ||
    /System Storage Summary/i.test(text)
  );
}

function durationToSeconds(str) {
  if (!str) return null;
  const d = /(\d+)\s*d/i.exec(str);
  const h = /(\d+)\s*h/i.exec(str);
  const m = /(\d+)\s*m(?!s)/i.exec(str);
  const s = /(\d+)\s*s/i.exec(str);
  if (!d && !h && !m && !s) return null;
  let total = 0;
  if (d) total += parseInt(d[1], 10) * 86400;
  if (h) total += parseInt(h[1], 10) * 3600;
  if (m) total += parseInt(m[1], 10) * 60;
  if (s) total += parseInt(s[1], 10);
  return total;
}

function secondsToHuman(sec) {
  if (sec === null || Number.isNaN(sec)) return "unknown";
  const d = Math.floor(sec / 86400);
  const h = Math.floor((sec % 86400) / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const parts = [];
  if (d) parts.push(`${d}d`);
  if (h) parts.push(`${h}h`);
  if (m) parts.push(`${m}m`);
  if (!parts.length) parts.push(`${sec % 60}s`);
  return parts.join(" ");
}

function getFormattedTimestampFilename() {
  const now = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  const y = now.getFullYear();
  const m = pad(now.getMonth() + 1);
  const d = pad(now.getDate());
  const hh = pad(now.getHours());
  const mm = pad(now.getMinutes());
  const ss = pad(now.getSeconds());
  return `${y}${m}${d}_${hh}${mm}${ss}`;
}

// ---------------------------------------------------------------------
// Input Classification
// ---------------------------------------------------------------------
function detectInputKind(text) {
  if (!text || !text.trim()) return "none";

  const hasFgtCliMarkers =
    /(?:^|\n)\s*#?\s*(?:get\s+system\s+status|get\s+system\s+performance\s+status|get\s+system\s+ha\s+status|diagnose\s+autoupdate\s+status|get\s+vpn\s+ipsec\s+tunnel\s+summary|diagnose\s+sys\s+sdwan\s+health-check|get\s+system\s+external-resource|show\s+system\s+interface|show\s+user\s+local|diagnose\s+user\s+ban\s+list|diagnose\s+test\s+application\s+miglogd|diagnose\s+hardware\s+sysinfo\s+conserve|diagnose\s+sys\s+session\s+stat|get\s+router\s+info\s+bgp\s+summary|get\s+router\s+info\s+ospf\s+neighbor|get\s+system\s+interface\s+physical|diagnose\s+netlink\s+interface\s+list|get\s+vpn\s+certificate\s+local|diagnose\s+debug\s+crashlog\s+read)\b/i.test(text) ||
    /FDN availability\s*:/i.test(text) ||
    /selectors\(total,up\):/i.test(text) ||
    /HA Health Status\s*:/i.test(text) ||
    /memory conserve mode:\s*(?:on|off)/i.test(text) ||
    /session_count=\d+/i.test(text);

  const hasFazCliMarkers =
    /Platform Full Name\s*:\s*FortiAnalyzer/i.test(text) ||
    /FortiAnalyzer-VM/i.test(text) ||
    /\bFAZVM\d*\b/i.test(text) ||
    /(?:^|\n)\s*#?\s*(?:diagnose\s+system\s+print\s+df|diagnose\s+log\s+device|diagnose\s+test\s+application\s+oftpd|diagnose\s+fortilogd\s+msgrate|diagnose\s+test\s+application\s+sqlplugind)\b/i.test(text) ||
    /System Storage Summary/i.test(text) ||
    /Log insert speed:\s*logs\//i.test(text);

  const hasConfigMarkers =
    /#conf_file_ver=/i.test(text) ||
    /#config-version=/i.test(text) ||
    (/(?:^|\n)\s*config\s+(?:firewall|vpn|router|switch)\b/i.test(text) && !hasFgtCliMarkers);

  if (hasFgtCliMarkers && hasFazCliMarkers) {
    return "dual";
  }
  if (hasFgtCliMarkers) {
    return "fgt";
  }
  if (hasFazCliMarkers) {
    return "faz";
  }
  if (hasConfigMarkers || /(?:^|\n)\s*config\s+/i.test(text)) {
    return "conf";
  }

  return "none";
}

// =====================================================================
// ENGINE 1: RUNTIME CLI ENGINE & UNIFIED CHECKS
// =====================================================================

/**
 * FGT-SYS-01: FortiGate System Uptime
 * Triggers: get system status or Uptime:
 * PASS: Uptime >= 24h.
 * WARN: Uptime < 24h.
 */
function checkFgtSystemUptime(text) {
  const hasUptimeHeader =
    hasCommand(text, "get system status") ||
    /(?:System\s+)?[Uu]ptime\s*:/i.test(text);

  if (!hasUptimeHeader) return null;

  const uptimeMatch =
    /(?:System\s+)?[Uu]ptime\s*:?\s*([0-9]+\s*days?,?\s*[0-9]+\s*hours?(?:,?\s*[0-9]+\s*minutes?)?|[0-9]+\s*hours?,?\s*[0-9]+\s*minutes?)/i.exec(
      text
    );

  if (!uptimeMatch) return null;

  const raw = uptimeMatch[1].trim();
  const dayMatch = /([0-9]+)\s*days?/i.exec(raw);
  const hourMatch = /([0-9]+)\s*hours?/i.exec(raw);
  const minMatch = /([0-9]+)\s*minutes?/i.exec(raw);

  const days = dayMatch ? parseInt(dayMatch[1], 10) : 0;
  const hours = hourMatch ? parseInt(hourMatch[1], 10) : 0;
  const mins = minMatch ? parseInt(minMatch[1], 10) : 0;
  const totalHours = days * 24 + hours + mins / 60;
  const data = { uptimeStr: raw, totalHours, days, hours, mins };

  if (totalHours < THRESHOLDS.fgtUptimeWarnHours) {
    return makeFinding({
      id: "FGT-SYS-01",
      component: "FortiGate System Uptime",
      status: "WARN",
      findingText: `Uptime is only ${raw} (< 24 hours). Indicates a recent reboot, power event, kernel crash, or uncoordinated firmware upgrade.`,
      actionText: "Review crash log ('diagnose debug crashlog read') and system event logs around reboot timestamp to verify planned vs unexpected reboot.",
      source: "cli",
      data
    });
  }

  return makeFinding({
    id: "FGT-SYS-01",
    component: "FortiGate System Uptime",
    status: "PASS",
    findingText: `Uptime is ${raw} (>= 24 hours). Continuous normal operation verified with no recent reboot detected.`,
    actionText: "",
    source: "cli",
    data
  });
}

/**
 * FGT-PERF-01: FortiGate Performance (CPU & Memory)
 * Triggers: get system performance status
 * Extracts Memory % from lines like:
 *   Memory: 23215592k total, 5634756k used (24.3%)
 *   Memory states: 45% used
 * Parses both CPU Idle/User and Memory % Used.
 * FAIL: CPU > 80% or Memory > 80%.
 * WARN: CPU > 60% or Memory > 70%.
 * PASS: Normal utilization.
 */
function checkFgtPerformance(text) {
  if (
    !hasCommand(text, "get system performance status") &&
    !/CPU states:[^\n]*idle/i.test(text) &&
    !/Memory:[^\n]*used/i.test(text)
  ) {
    return null;
  }

  let cpuUsed = null;
  const cpuIdleMatch = /CPU states:[^\n]*?([0-9]+(?:\.[0-9]+)?)%\s*idle/i.exec(text);
  if (cpuIdleMatch) {
    cpuUsed = Math.round((100 - parseFloat(cpuIdleMatch[1])) * 10) / 10;
  } else {
    const userMatch = /([0-9]+(?:\.[0-9]+)?)%\s*user/i.exec(text);
    const sysMatch = /([0-9]+(?:\.[0-9]+)?)%\s*system/i.exec(text);
    if (userMatch || sysMatch) {
      const u = userMatch ? parseFloat(userMatch[1]) : 0;
      const s = sysMatch ? parseFloat(sysMatch[1]) : 0;
      cpuUsed = Math.round((u + s) * 10) / 10;
    }
  }

  let memUsed = null;
  const memParenMatch = /Memory:[^\n]*?\(([0-9]+(?:\.[0-9]+)?)%\)/i.exec(text);
  const memStatesMatch = /Memory states:\s*([0-9]+(?:\.[0-9]+)?)%\s*used/i.exec(text);
  const memSimpleMatch = /Memory:\s*([0-9]+(?:\.[0-9]+)?)%\s*used/i.exec(text);

  if (memParenMatch) {
    memUsed = parseFloat(memParenMatch[1]);
  } else if (memStatesMatch) {
    memUsed = parseFloat(memStatesMatch[1]);
  } else if (memSimpleMatch) {
    memUsed = parseFloat(memSimpleMatch[1]);
  } else {
    const memCalcMatch = /Memory:\s*([0-9]+)k\s*total,\s*([0-9]+)k\s*used/i.exec(text);
    if (memCalcMatch) {
      const total = parseFloat(memCalcMatch[1]);
      const used = parseFloat(memCalcMatch[2]);
      if (total > 0) {
        memUsed = Math.round((used / total) * 1000) / 10;
      }
    }
  }

  if (cpuUsed === null && memUsed === null) return null;

  const cpuStr = cpuUsed !== null ? `CPU ${cpuUsed}% used` : "CPU N/A";
  const memStr = memUsed !== null ? `Memory ${memUsed}% used` : "Memory N/A";
  const summary = `${cpuStr}, ${memStr}`;

  const isFail =
    (cpuUsed !== null && cpuUsed > THRESHOLDS.fgtCpuFail) ||
    (memUsed !== null && memUsed > THRESHOLDS.fgtMemFail);
  const isWarn =
    (cpuUsed !== null && cpuUsed > THRESHOLDS.fgtCpuWarn) ||
    (memUsed !== null && memUsed > THRESHOLDS.fgtMemWarn);

  const data = { cpu: cpuUsed, mem: memUsed, summary };

  if (isFail) {
    return makeFinding({
      id: "FGT-PERF-01",
      component: "FortiGate Performance",
      status: "FAIL",
      findingText: `Critical utilization: ${summary}. Exceeds FAIL thresholds (CPU > ${THRESHOLDS.fgtCpuFail}% or Memory > ${THRESHOLDS.fgtMemFail}%).`,
      actionText: "Identify high-consumption daemons via 'diagnose sys top'. Check for traffic spikes, proxy-worker runaway, or conserve mode, and schedule maintenance if sustained.",
      source: "cli",
      data
    });
  }

  if (isWarn) {
    return makeFinding({
      id: "FGT-PERF-01",
      component: "FortiGate Performance",
      status: "WARN",
      findingText: `Elevated utilization: ${summary}. Exceeds WARN thresholds (CPU > ${THRESHOLDS.fgtCpuWarn}% or Memory > ${THRESHOLDS.fgtMemWarn}%).`,
      actionText: "Monitor utilization trajectory over next check cycle; investigate top processes if memory or CPU continues to climb.",
      source: "cli",
      data
    });
  }

  return makeFinding({
    id: "FGT-PERF-01",
    component: "FortiGate Performance",
    status: "PASS",
    findingText: `Normal utilization: ${summary} (within healthy operational parameters).`,
    actionText: "",
    source: "cli",
    data
  });
}

/**
 * FGT-MEM-02: Kernel Memory Conserve State
 * Command: diagnose hardware sysinfo conserve
 * FAIL: mode === "on" (kernel dropping sessions to prevent OS crash)
 * WARN: mode === "off" AND (red_threshold - used_pct <= 5 OR used_pct >= 80)
 * PASS: mode === "off" and RAM headroom is sufficient.
 */
function checkFgtMemoryConserve(text) {
  if (
    !hasCommand(text, "diagnose hardware sysinfo conserve") &&
    !/conserve mode:/i.test(text)
  ) {
    return null;
  }

  const modeMatch = /(?:system |memory )?conserve mode:\s*(on|off)/i.exec(text);
  if (!modeMatch) return null;

  const mode = modeMatch[1].toLowerCase();

  const usedMatch =
    /memory used:\s*\d+\s*MB\s+(\d+(?:\.\d+)?)%/i.exec(text) ||
    /(?:total RAM:[^\n]*?|\bused:\s*\d+\s*MB\s*)\(([0-9.]+)%\)/i.exec(text) ||
    /used\s*pct[^\n]*?([0-9.]+)%/i.exec(text) ||
    /RAM used:\s*([0-9.]+)%/i.exec(text);
  const used_pct = usedMatch ? parseFloat(usedMatch[1]) : null;

  const thr = (n) =>
    new RegExp("(?:memory used )?threshold\s+" + n + ":\s*\d+\s*MB\s+(\d+)%", "i").exec(text) ||
    new RegExp(n + "\s+threshold:\s*(\d+)%", "i").exec(text);

  const redMatch = thr("red");
  const extremeMatch = thr("extreme");
  const greenMatch = thr("green");

  const red_threshold = redMatch ? parseInt(redMatch[1], 10) : null;
  const extreme_threshold = extremeMatch ? parseInt(extremeMatch[1], 10) : null;
  const green_threshold = greenMatch ? parseInt(greenMatch[1], 10) : null;

  const data = { mode, used_pct, red_threshold, extreme_threshold, green_threshold };

  if (mode === "on") {
    return makeFinding({
      id: "FGT-MEM-02",
      component: "Kernel Memory Conserve State",
      status: "FAIL",
      findingText: `Kernel memory conserve mode is ON (RAM usage: ${used_pct !== null ? `${used_pct}%` : "N/A"}). FortiGate is dropping new sessions or non-essential traffic to prevent OS crash.`,
      actionText: "Identify high memory consuming daemons via 'diagnose sys top' or 'diagnose sys process bucket list', reduce proxy workers, or upgrade hardware RAM capacity.",
      source: "cli",
      data
    });
  }

  const tightHeadroom = red_threshold !== null && used_pct !== null && (red_threshold - used_pct <= 5);
  const highRam = used_pct !== null && used_pct >= 80;

  if (tightHeadroom || highRam) {
    let detail = `RAM usage is ${used_pct}%`;
    if (red_threshold !== null) detail += ` (red threshold: ${red_threshold}%)`;
    return makeFinding({
      id: "FGT-MEM-02",
      component: "Kernel Memory Conserve State",
      status: "WARN",
      findingText: `Kernel memory conserve mode is OFF, but ${detail}. High memory pressure detected.`,
      actionText: "Monitor process memory usage and prepare optimization or capacity expansion before memory conserve mode triggers.",
      source: "cli",
      data
    });
  }

  return makeFinding({
    id: "FGT-MEM-02",
    component: "Kernel Memory Conserve State",
    status: "PASS",
    findingText: `Kernel memory conserve mode is OFF. RAM usage (${used_pct !== null ? `${used_pct}%` : "healthy"}) is operating safely within normal bounds.`,
    actionText: "",
    source: "cli",
    data
  });
}

/**
 * FGT-SESS-01: Session Table & Ephemeral Port Saturation
 * Command: diagnose sys session stat
 * FAIL: memory_tension_drop > 0 OR (ephemeral_total > 0 AND (ephemeral_used / ephemeral_total) >= 0.95)
 * WARN: ephemeral_total > 0 AND (ephemeral_used / ephemeral_total) >= 0.80
 * PASS: No memory tension drops and ephemeral port usage < 80%.
 */
function checkFgtSessionStat(text) {
  if (
    !hasCommand(text, "diagnose sys session stat") &&
    !/session_count=/i.test(text)
  ) {
    return null;
  }

  const sessionMatch = /session_count=(\d+)\s+setup_rate=(\d+)\s+exp_count=(\d+)/i.exec(text);
  const tensionMatch = /memory_tension_drop=(\d+)/i.exec(text);
  const ephemeralMatch = /ephemeral=(\d+)\/(\d+)/i.exec(text);

  if (!sessionMatch && !tensionMatch && !ephemeralMatch) return null;

  const session_count = sessionMatch ? parseInt(sessionMatch[1], 10) : 0;
  const setup_rate = sessionMatch ? parseInt(sessionMatch[2], 10) : 0;
  const exp_count = sessionMatch ? parseInt(sessionMatch[3], 10) : 0;
  const memory_tension_drop = tensionMatch ? parseInt(tensionMatch[1], 10) : 0;

  const ephemeral_used = ephemeralMatch ? parseInt(ephemeralMatch[1], 10) : 0;
  const ephemeral_total = ephemeralMatch ? parseInt(ephemeralMatch[2], 10) : 0;
  const ephemeral_ratio = `${ephemeral_used}/${ephemeral_total}`;

  const data = {
    session_count,
    setup_rate,
    memory_tension_drop,
    ephemeral_ratio
  };

  const ephRatioVal = ephemeral_total > 0 ? (ephemeral_used / ephemeral_total) : 0;

  if (memory_tension_drop > 0 || (ephemeral_total > 0 && ephRatioVal >= 0.95)) {
    let reason = "";
    if (memory_tension_drop > 0) {
      reason = `Memory tension drops detected (${memory_tension_drop} drops). Session allocation is actively failing due to memory pressure.`;
    } else {
      reason = `Ephemeral port table near exhaustion (${ephemeral_ratio}, ${Math.round(ephRatioVal * 100)}%). Source NAT allocation failure imminent.`;
    }

    return makeFinding({
      id: "FGT-SESS-01",
      component: "Session Table & Ephemeral Ports",
      status: "FAIL",
      findingText: `Session table saturation critical: ${reason}`,
      actionText: "Check for session floods/SYN attacks, review session TTL timeouts, or add additional IP addresses to IP pool for source NAT.",
      source: "cli",
      data
    });
  }

  if (ephemeral_total > 0 && ephRatioVal >= 0.80) {
    return makeFinding({
      id: "FGT-SESS-01",
      component: "Session Table & Ephemeral Ports",
      status: "WARN",
      findingText: `Elevated ephemeral port utilization (${ephemeral_ratio}, ${Math.round(ephRatioVal * 100)}%). Session setup rate is ${setup_rate}/s.`,
      actionText: "Monitor NAT IP pool utilization and consider expanding IP pools before exhaustion occurs.",
      source: "cli",
      data
    });
  }

  return makeFinding({
    id: "FGT-SESS-01",
    component: "Session Table & Ephemeral Ports",
    status: "PASS",
    findingText: `Session table state healthy: ${session_count} active sessions, setup rate ${setup_rate}/s, 0 memory tension drops, ephemeral port usage ${ephemeral_ratio}.`,
    actionText: "",
    source: "cli",
    data
  });
}

/**
 * FGT-NET-01: Physical Interface Link, Speed & Duplex
 * Command: get system interface physical
 * FAIL: Any interface reporting status: up with duplex: half
 * WARN: Any operational uplink/port reporting status: up with speed <= 100 Mbps (excluding mgmt)
 * PASS: All active links report full duplex and expected speeds (>= 1000 Mbps).
 */
function checkFgtPhysicalInterfaces(text) {
  if (
    !hasCommand(text, "get system interface physical") &&
    !/==\s*\[[^\]]+\]/i.test(text) &&
    !/speed:\s*\d+\s*Mbps/i.test(text)
  ) {
    return null;
  }

  const interfaces = [];
  let cur = null;
  for (const line of text.split(/\r?\n/)) {
    const hd = /^\s*==\s*\[\s*([^\]\s]+)\s*\]/.exec(line);
    if (hd) cur = { name: hd[1], status: null };
    if (!cur) continue;
    const st = /\bstatus:\s*(up|down)/i.exec(line);
    if (st) cur.status = st[1].toLowerCase();
    const sp = /\bspeed:\s*(\d+)\s*Mbps\s*\(Duplex:\s*(full|half)\)/i.exec(line);
    if (sp && cur.status) {
      interfaces.push({
        name: cur.name,
        status: cur.status,
        speed: parseInt(sp[1], 10),
        duplex: sp[2].toLowerCase()
      });
      cur = null;
    }
  }

  // Fallback regex for single-line format
  if (!interfaces.length) {
    const intfRe = /==\s*\[([^\]]+)\],?\s*status:\s*(up|down),?\s*speed:\s*(\d+)\s*Mbps\s*\(Duplex:\s*(full|half)\)/gi;
    let match;
    while ((match = intfRe.exec(text)) !== null) {
      interfaces.push({
        name: match[1].trim(),
        status: match[2].toLowerCase(),
        speed: parseInt(match[3], 10),
        duplex: match[4].toLowerCase()
      });
    }
  }

  if (!interfaces.length) return null;

  const data = { interfaces };

  const activeIntfs = interfaces.filter(i => i.status === "up");
  const halfDuplexIntfs = activeIntfs.filter(i => i.duplex === "half");
  const slowSpeedIntfs = activeIntfs.filter(i => i.speed <= 100 && !/mgmt|ilo|oob|ha\b/i.test(i.name));

  if (halfDuplexIntfs.length > 0) {
    const listStr = halfDuplexIntfs.map(i => `${i.name} (${i.speed}Mbps ${i.duplex})`).join(", ");
    return makeFinding({
      id: "FGT-NET-01",
      component: "Physical Interface Link & Duplex",
      status: "FAIL",
      findingText: `Duplex mismatch detected on active physical interface(s): ${listStr}. Half-duplex operation causes packet collisions, latency, and severe throughput loss.`,
      actionText: "Verify auto-negotiation settings on firewall and connected switch ports, ensuring both sides match (auto/auto or hardcoded full-duplex).",
      source: "cli",
      data
    });
  }

  if (slowSpeedIntfs.length > 0) {
    const listStr = slowSpeedIntfs.map(i => `${i.name} (${i.speed}Mbps ${i.duplex})`).join(", ");
    return makeFinding({
      id: "FGT-NET-01",
      component: "Physical Interface Link & Duplex",
      status: "WARN",
      findingText: `Suboptimal link speed detected on active physical interface(s): ${listStr}. Operational rate is <= 100Mbps.`,
      actionText: "Inspect Ethernet cabling (Cat5e/Cat6 requirement), patch panels, and switch port speed negotiation settings.",
      source: "cli",
      data
    });
  }

  return makeFinding({
    id: "FGT-NET-01",
    component: "Physical Interface Link & Duplex",
    status: "PASS",
    findingText: `All ${activeIntfs.length} active physical interface(s) report optimal link speed (>= 1Gbps) and full-duplex operation.`,
    actionText: "",
    source: "cli",
    data
  });
}

function parseFortiCertDate(dateStr) {
  if (!dateStr || typeof dateStr !== "string") return null;
  const clean = dateStr.trim();
  
  // Try native parse first
  const nativeParsed = new Date(clean);
  if (!isNaN(nativeParsed.getTime())) return nativeParsed;

  // Format: "12:00:00 Sun Mar 15 2026 GMT" or "Sun Mar 15 12:00:00 2026 GMT"
  const parts = clean.replace(/GMT|UTC/i, "").trim().split(/\s+/);
  const monthMap = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
  
  let year = null, month = null, day = null;
  for (const p of parts) {
    const m = p.toLowerCase().substring(0, 3);
    if (monthMap[m] !== undefined && month === null) {
      month = monthMap[m];
    } else if (/^\d{4}$/.test(p) && year === null) {
      year = parseInt(p, 10);
    } else if (/^\d{1,2}$/.test(p) && day === null) {
      day = parseInt(p, 10);
    }
  }

  if (year !== null && month !== null && day !== null) {
    return new Date(Date.UTC(year, month, day));
  }
  return null;
}

/**
 * FGT-CERT-01: Local SSL/VPN Certificate Expiration
 * Command: get vpn certificate local details
 * FAIL: Any certificate where daysRemaining <= 0 (expired) OR daysRemaining <= 14.
 * WARN: daysRemaining > 14 AND daysRemaining <= 60.
 * PASS: All active local certificates have daysRemaining > 60.
 */
function checkFgtCertificates(text) {
  if (
    !hasCommand(text, "get vpn certificate local details") &&
    !hasCommand(text, "get vpn certificate local") &&
    !(/Valid to:/i.test(text) && /Certificate Name:/i.test(text))
  ) {
    return null;
  }

  const certificates = [];
  const certBlockRe = /(?:Certificate Name:\s*(\S+)|==\s*\[\s*(\S+)\s*\])([\s\S]*?)(?=(?:Certificate Name:|==\s*\[|$))/gi;

  let match;
  while ((match = certBlockRe.exec(text)) !== null) {
    const name = match[1] || match[2];
    const body = match[3] || "";
    const validToMatch = /Valid to:\s*([^\r\n]+)/i.exec(body);
    if (name && validToMatch) {
      const validToDate = parseFortiCertDate(validToMatch[1]);
      if (validToDate && !isNaN(validToDate.getTime())) {
        const daysRemaining = Math.floor((validToDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
        certificates.push({
          name,
          daysRemaining,
          validTo: validToDate.toISOString().split("T")[0]
        });
      }
    }
  }

  if (!certificates.length) {
    const nameMatch = /Certificate Name:\s*(\S+)/i.exec(text);
    const validToMatch = /Valid to:\s*([^\r\n]+)/i.exec(text);
    if (nameMatch && validToMatch) {
      const name = nameMatch[1].trim();
      const validToDate = parseFortiCertDate(validToMatch[1]);
      if (validToDate && !isNaN(validToDate.getTime())) {
        const daysRemaining = Math.floor((validToDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
        certificates.push({
          name,
          daysRemaining,
          validTo: validToDate.toISOString().split("T")[0]
        });
      }
    }
  }

  if (!certificates.length) return null;

  const data = { certificates };

  const expiredOrCritical = certificates.filter(c => c.daysRemaining <= 14);
  const warningCerts = certificates.filter(c => c.daysRemaining > 14 && c.daysRemaining <= 60);

  if (expiredOrCritical.length > 0) {
    const bullets = expiredOrCritical
      .map(c => `  • ${c.name}: ${c.daysRemaining <= 0 ? "EXPIRED" : `${c.daysRemaining} days left`} (Valid to: ${c.validTo})`)
      .join("\n");
    return makeFinding({
      id: "FGT-CERT-01",
      component: "Local SSL/VPN Certificates",
      status: "FAIL",
      findingText: `${expiredOrCritical.length} local certificate(s) expired or expiring imminently (<= 14 days):\n${bullets}`,
      actionText: "Renew or replace expiring local certificates immediately to prevent SSL-VPN connection outages or administrative GUI access errors.",
      source: "cli",
      data
    });
  }

  if (warningCerts.length > 0) {
    const bullets = warningCerts
      .map(c => `  • ${c.name}: ${c.daysRemaining} days left (Valid to: ${c.validTo})`)
      .join("\n");
    return makeFinding({
      id: "FGT-CERT-01",
      component: "Local SSL/VPN Certificates",
      status: "WARN",
      findingText: `${warningCerts.length} local certificate(s) expiring within 60 days:\n${bullets}`,
      actionText: "Schedule certificate CSR generation and renewal prior to expiration date.",
      source: "cli",
      data
    });
  }

  const allCerts = certificates
    .map(c => `  • ${c.name}: ${c.daysRemaining} days left (Valid to: ${c.validTo})`)
    .join("\n");
  return makeFinding({
    id: "FGT-CERT-01",
    component: "Local SSL/VPN Certificates",
    status: "PASS",
    findingText: `All ${certificates.length} local SSL/VPN certificate(s) are valid with over 60 days remaining before expiration:\n${allCerts}`,
    actionText: "",
    source: "cli",
    data
  });
}

/**
 * FGT-RT-BGP-01: BGP Neighbor Peering & State Engine
 * Command: get router info bgp summary
 * INFO: BGP not active (% BGP instance not found or no summary/neighbors)
 * FAIL: Configured neighbor in Idle, Active, Connect, OpenSent, or OpenConfirm.
 * WARN: Neighbor Established but 0 prefixes received, or Up/Down timer < 5 minutes.
 * PASS: All peers Established with prefixes > 0.
 */
function checkFgtBgpSummary(text) {
  if (
    !hasCommand(text, "get router info bgp summary") &&
    !/BGP neighbor/i.test(text) &&
    !/BGP summary/i.test(text) &&
    !/BGP instance/i.test(text) &&
    !/BGP table version/i.test(text)
  ) {
    return null;
  }

  if (/% BGP instance not found/i.test(text)) {
    return makeFinding({
      id: "FGT-RT-BGP-01",
      component: "BGP Neighbor Peering & State",
      status: "INFO",
      findingText: "BGP is not active on this device (routing daemon returned instance not found).",
      actionText: "",
      source: "cli",
      data: { peers: [] }
    });
  }

  const peers = [];
  const tableLineRe = /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)/gm;

  let match;
  while ((match = tableLineRe.exec(text)) !== null) {
    const ip = match[1];
    const as = parseInt(match[3], 10);
    const upDown = match[9];
    const rawStatePfx = match[10];

    let state = "Established";
    let prefixes = 0;

    if (/^\d+$/.test(rawStatePfx)) {
      state = "Established";
      prefixes = parseInt(rawStatePfx, 10);
    } else {
      state = rawStatePfx;
      prefixes = 0;
    }

    peers.push({ ip, as, state, prefixes, upDown });
  }

  if (peers.length === 0) {
    const detailBlockRe = /BGP neighbor is (\d{1,3}(?:\.\d{1,3}){3}), remote AS (\d+)[\s\S]*?BGP state = (\w+)(?:[\s\S]*?up for (\S+))?/gi;
    let dm;
    while ((dm = detailBlockRe.exec(text)) !== null) {
      peers.push({
        ip: dm[1],
        as: parseInt(dm[2], 10),
        state: dm[3],
        prefixes: 0,
        upDown: dm[4] || "00:00:00"
      });
    }
  }

  if (peers.length === 0) {
    return makeFinding({
      id: "FGT-RT-BGP-01",
      component: "BGP Neighbor Peering & State",
      status: "INFO",
      findingText: "BGP is not active or no BGP neighbors are configured on this device.",
      actionText: "",
      source: "cli",
      data: { peers: [] }
    });
  }

  const data = { peers };

  const downPeers = peers.filter(p => p.state.toLowerCase() !== "established");
  const zeroPfxPeers = peers.filter(p => p.state.toLowerCase() === "established" && p.prefixes === 0);
  const recentFlapPeers = peers.filter(p => p.state.toLowerCase() === "established" && /^00:0[0-4]:/i.test(p.upDown));

  const allPeerBullets = peers
    .map(p => `  • Peer ${p.ip} (Remote AS ${p.as}): State = ${p.state}, Received Prefixes = ${p.prefixes}, Session Uptime = ${p.upDown}`)
    .join("\n");

  const healthyBaseline = "All configured peers Established with PfxRcd > 0 and stable session uptime (> 5 minutes).";
  const triageAction = "Inspect route-map export filters and prefix-limits on peer and firewall. Check received routes via: get router info bgp neighbors <peer-ip> received-routes.";

  if (downPeers.length > 0) {
    return makeFinding({
      id: "FGT-RT-BGP-01",
      component: "BGP Neighbor Peering & State",
      status: "FAIL",
      findingText: `${downPeers.length} of ${peers.length} BGP neighbor(s) are in non-established state:\n${allPeerBullets}\n\nRoot Cause & Meaning: BGP session is down. Dynamic routes are withdrawn, causing traffic routing failures or blackholing.\nHealthy Baseline: ${healthyBaseline}`,
      actionText: triageAction,
      source: "cli",
      data
    });
  }

  if (zeroPfxPeers.length > 0 || recentFlapPeers.length > 0) {
    let rootCause = "";
    if (zeroPfxPeers.length > 0) {
      rootCause = "The BGP TCP connection (port 179) is active, but 0 routes are being received. Traffic will not dynamically route through this upstream carrier/hub.";
    } else {
      rootCause = "Recent BGP session flap detected (< 5m uptime). Route oscillation may degrade convergence and cause transient packet drops.";
    }

    return makeFinding({
      id: "FGT-RT-BGP-01",
      component: "BGP Neighbor Peering & State",
      status: "WARN",
      findingText: `BGP peering instability or zero prefix exchange:\n${allPeerBullets}\n\nRoot Cause & Meaning: ${rootCause}\nHealthy Baseline: ${healthyBaseline}`,
      actionText: triageAction,
      source: "cli",
      data
    });
  }

  return makeFinding({
    id: "FGT-RT-BGP-01",
    component: "BGP Neighbor Peering & State",
    status: "PASS",
    findingText: `All ${peers.length} BGP neighbor peering session(s) established and healthy with active prefix exchanges:\n${allPeerBullets}\n\nHealthy Baseline: ${healthyBaseline}`,
    actionText: "",
    source: "cli",
    data
  });
}

/**
 * FGT-RT-OSPF-01: OSPF Adjacency & State Audit
 * Command: get router info ospf neighbor
 * INFO: Empty output or "OSPF is not enabled"
 * FAIL: Neighbors stuck in Init, ExStart, Exchange, Loading, or Down.
 * PASS: Neighbors in Full (or 2-Way/DROther on broadcast LANs).
 */
function checkFgtOspfNeighbors(text) {
  if (
    !hasCommand(text, "get router info ospf neighbor") &&
    !/Neighbor ID/i.test(text) &&
    !/ospf neighbor/i.test(text)
  ) {
    return null;
  }

  if (/OSPF is not enabled/i.test(text)) {
    return makeFinding({
      id: "FGT-RT-OSPF-01",
      component: "OSPF Neighbor Adjacency",
      status: "INFO",
      findingText: "OSPF is not enabled or no neighbors detected.",
      actionText: "",
      source: "cli",
      data: { neighbors: [] }
    });
  }

  const neighbors = [];
  const ospfLineRe = /^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+([A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)?)\s+(\S+)\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\S+)/gm;

  let match;
  while ((match = ospfLineRe.exec(text)) !== null) {
    const neighborId = match[1];
    const priority = parseInt(match[2], 10);
    const rawState = match[3];
    const deadTime = match[4];
    const ip = match[5];
    const iface = match[6];
    const baseState = rawState.split("/")[0];

    neighbors.push({
      neighborId,
      priority,
      rawState,
      baseState,
      deadTime,
      ip,
      interface: iface
    });
  }

  if (neighbors.length === 0) {
    return makeFinding({
      id: "FGT-RT-OSPF-01",
      component: "OSPF Neighbor Adjacency",
      status: "INFO",
      findingText: "OSPF is not enabled or no OSPF neighbors detected.",
      actionText: "",
      source: "cli",
      data: { neighbors: [] }
    });
  }

  const data = { neighbors };

  const stuckNeighbors = neighbors.filter(n => ["init", "exstart", "exchange", "loading", "down"].includes(n.baseState.toLowerCase()));

  if (stuckNeighbors.length > 0) {
    const detail = stuckNeighbors.map(n => `${n.neighborId} (${n.rawState} on ${n.interface})`).join(", ");
    return makeFinding({
      id: "FGT-RT-OSPF-01",
      component: "OSPF Neighbor Adjacency",
      status: "FAIL",
      findingText: `${stuckNeighbors.length} of ${neighbors.length} OSPF neighbor(s) stuck in non-operational state: ${detail}.`,
      actionText: "Check OSPF MTU matching (mtu-ignore), subnet mask alignment, area ID matching, authentication keys, and Hello/Dead timer settings.",
      source: "cli",
      data
    });
  }

  return makeFinding({
    id: "FGT-RT-OSPF-01",
    component: "OSPF Neighbor Adjacency",
    status: "PASS",
    findingText: `All ${neighbors.length} OSPF neighbor adjacency(ies) operational and fully synchronized (Full/2-Way state).`,
    actionText: "",
    source: "cli",
    data
  });
}

/**
 * FGT-NET-02: Normalized Interface Error & Drop Ratios
 * Command: diagnose netlink interface list
 * Qualification: Process only active interfaces where total packets (rxp + txp) >= 100,000.
 * FAIL: col > 0 OR error_ratio >= 0.001 (0.1%) OR drop_ratio >= 0.01 (1.0%).
 * WARN: error_ratio >= 0.0001 (0.01%) OR drop_ratio >= 0.001 (0.1%).
 * PASS: Negligible or zero error/drop ratio across high-traffic interfaces.
 */
function checkFgtNetlinkErrorRatios(text) {
  if (
    !hasCommand(text, "diagnose netlink interface list") &&
    !/stat:\s+rxp=/i.test(text)
  ) {
    return null;
  }

  const interfaces = [];
  const blockRe = /(?:if|name)=([^\s\n\r]+)[\s\S]*?stat:\s+rxp=(\d+)\s+txp=(\d+).*?rxe=(\d+)\s+txe=(\d+)\s+rxd=(\d+)\s+txd=(\d+).*?collision=(\d+)/gi;

  let match;
  while ((match = blockRe.exec(text)) !== null) {
    const name = match[1];
    const rxp = parseInt(match[2], 10);
    const txp = parseInt(match[3], 10);
    const rxe = parseInt(match[4], 10);
    const txe = parseInt(match[5], 10);
    const rxd = parseInt(match[6], 10);
    const txd = parseInt(match[7], 10);
    const collision = parseInt(match[8], 10);

    const totalPkts = rxp + txp;
    if (totalPkts >= 100000) {
      const totalErrors = rxe + txe;
      const totalDrops = rxd + txd;
      const error_ratio = totalPkts > 0 ? (totalErrors / totalPkts) : 0;
      const drop_ratio = totalPkts > 0 ? (totalDrops / totalPkts) : 0;

      interfaces.push({
        name,
        rxp,
        txp,
        rxe,
        txe,
        rxd,
        txd,
        collision,
        error_ratio: Math.round(error_ratio * 100000) / 100000,
        drop_ratio: Math.round(drop_ratio * 100000) / 100000
      });
    }
  }

  if (!interfaces.length) return null;

  const data = { interfaces };

  const failIntfs = interfaces.filter(i => i.collision > 0 || i.error_ratio >= 0.001 || i.drop_ratio >= 0.01);
  const warnIntfs = interfaces.filter(i => !failIntfs.includes(i) && (i.error_ratio >= 0.0001 || i.drop_ratio >= 0.001));

  if (failIntfs.length > 0) {
    const bullets = failIntfs
      .map(i => `  • Interface '${i.name}': Errors = ${(i.error_ratio * 100).toFixed(3)}%, Drops = ${(i.drop_ratio * 100).toFixed(3)}%, Collisions = ${i.collision}`)
      .join("\n");
    return makeFinding({
      id: "FGT-NET-02",
      component: "Interface Error & Drop Ratios",
      status: "FAIL",
      findingText: `Interface error/drop saturation critical on ${failIntfs.length} high-traffic port(s):\n${bullets}`,
      actionText: "Inspect physical fiber/copper transceivers, check CRC framing errors on switch ports, or investigate driver/ASIC buffer drops.",
      source: "cli",
      data
    });
  }

  if (warnIntfs.length > 0) {
    const bullets = warnIntfs
      .map(i => `  • Interface '${i.name}': Errors = ${(i.error_ratio * 100).toFixed(3)}%, Drops = ${(i.drop_ratio * 100).toFixed(3)}%`)
      .join("\n");
    return makeFinding({
      id: "FGT-NET-02",
      component: "Interface Error & Drop Ratios",
      status: "WARN",
      findingText: `Elevated error or drop ratio on ${warnIntfs.length} physical interface(s):\n${bullets}`,
      actionText: "Monitor interface counters for climbing errors and verify physical cable seating.",
      source: "cli",
      data
    });
  }

  const allIntfs = interfaces
    .map(i => `  • Interface '${i.name}': Errors = ${(i.error_ratio * 100).toFixed(3)}%, Drops = ${(i.drop_ratio * 100).toFixed(3)}%`)
    .join("\n");
  return makeFinding({
    id: "FGT-NET-02",
    component: "Interface Error & Drop Ratios",
    status: "PASS",
    findingText: `All ${interfaces.length} high-traffic physical interface(s) report clean performance with zero collisions and negligible error/drop ratios (< 0.01%):\n${allIntfs}`,
    actionText: "",
    source: "cli",
    data
  });
}

/**
 * FGT-SYS-03: Daemon Crash Log History
 * Command: diagnose debug crashlog read
 * Buffer: Deep forensic extraction of ALL daemon crashes from the crashlog.
 * FAIL: Any critical core daemon (wad, ipsengine, miglogd, sslvpnd, iked, httpsd, scanunit, forticron, authd) crashed in the last 24h, OR any single daemon crashed >= 3 times within 7 days.
 * WARN: Any daemon crashed 1-2 times within the last 7 days.
 * PASS: Clean log or no crashes in the last 7 days.
 */
function checkFgtCrashlogHistory(text) {
  if (
    !text ||
    (!hasCommand(text, "diagnose debug crashlog read") &&
      !/crashlog/i.test(text) &&
      !/\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}.*?(?:application|signal|crashed|previously\s+crashed|watchdog)/i.test(text))
  ) {
    return null;
  }

  const CRITICAL_CORE_DAEMONS = new Set([
    "wad",
    "ipsengine",
    "miglogd",
    "sslvpnd",
    "iked",
    "httpsd",
    "scanunit",
    "forticron",
    "authd"
  ]);

  const DAEMON_IMPACT_MAP = {
    httpsd: "Administrative GUI loss",
    sslvpnd: "SSL VPN Tunnel termination",
    scanunit: "AV/DLP scanning halt",
    wad: "Web proxy & explicit/transparent proxy worker crash",
    ipsengine: "IPS Engine inspection failure & threat bypass risk",
    miglogd: "Logging daemon failure & Syslog/FAZ reporting halt",
    iked: "IPsec daemon crash & VPN tunnel collapse",
    forticron: "Scheduled task scheduler crash",
    authd: "Authentication daemon failure (LDAP/RADIUS)",
    dnsproxy: "DNS proxy failure & resolution stoppage",
    snmpd: "SNMP monitoring agent crash",
    dhcpd: "DHCP service failure",
    cw_acd: "Wireless controller AP management crash"
  };

  function formatSignalReason(sigNum, rawSigDesc = "") {
    const num = parseInt(sigNum, 10);
    if (num === 11) return "Signal 11 / Segfault";
    if (num === 6) return "Signal 6 / Process Abort";
    if (num === 10) return "Signal 10 / Bus Error";
    if (num === 15) return "Signal 15 / Terminated";
    if (num === 9) return "Signal 9 / Killed";
    if (num === 4) return "Signal 4 / Illegal Instruction";
    if (rawSigDesc && rawSigDesc.trim()) {
      const cleanDesc = rawSigDesc.trim();
      if (/segmentation/i.test(cleanDesc)) return "Signal 11 / Segfault";
      if (/abort/i.test(cleanDesc)) return "Signal 6 / Process Abort";
      if (/bus/i.test(cleanDesc)) return "Signal 10 / Bus Error";
      return `Signal ${num} (${cleanDesc})`;
    }
    return `Signal ${num}`;
  }

  function parseCrashDate(dateStr) {
    if (!dateStr) return null;
    const d = new Date(dateStr.replace(" ", "T") + "Z");
    return isNaN(d.getTime()) ? null : d;
  }

  // 1. Isolate the crashlog section if diagnostic command was run
  let logText = text;
  const cmdMatch = /(?:^|\n)\s*#?\s*diagnose\s+debug\s+crashlog\s+read\b/i.exec(text);
  if (cmdMatch) {
    const afterCmd = text.slice(cmdMatch.index + cmdMatch[0].length);
    const nextPrompt = /\r?\n(?:\S+[#\$]\s*|#\s*|[a-zA-Z0-9_\-]+(?:\s*\([^\)]+\))?\s*#|(?:get|diagnose|show|config|execute)\s+)/i.exec(afterCmd);
    logText = nextPrompt ? afterCmd.slice(0, nextPrompt.index) : afterCmd;
  } else {
    const lines = text.split(/\r?\n/);
    const crashIndices = [];
    for (let i = 0; i < lines.length; i++) {
      if (/application|\b(?:signal\s+\d+|crashlog|crashed\s+in|previously\s+crashed|watchdog\s+timeout)\b/i.test(lines[i])) {
        crashIndices.push(i);
      }
    }
    if (crashIndices.length > 0) {
      const minIdx = Math.max(0, crashIndices[0] - 10);
      const maxIdx = Math.min(lines.length, crashIndices[crashIndices.length - 1] + 10);
      logText = lines.slice(minIdx, maxIdx).join("\n");
    }
  }

  const daemons = new Map();
  const seenSignatures = new Set();
  const now = Date.now();

  function getOrCreateDaemon(appName) {
    const norm = appName.toLowerCase().trim();
    if (!daemons.has(norm)) {
      daemons.set(norm, {
        app: norm,
        displayName: appName.trim(),
        totalCrashes: 0,
        latestTimestamp: "",
        latestDate: null,
        latestHoursAgo: 9999,
        reasons: new Map(),
        crashesLast24h: 0,
        crashesLast7d: 0,
        crashEvents: []
      });
    }
    return daemons.get(norm);
  }

  function recordDaemonCrash(appName, dateStr, reason, count = 1) {
    if (!appName) return;
    const cleanApp = appName.replace(/[,:<>]/g, "").trim();
    if (!cleanApp) return;

    const d = getOrCreateDaemon(cleanApp);
    const crashDate = parseCrashDate(dateStr);
    let hoursAgo = 0;
    if (crashDate) {
      hoursAgo = Math.max(0, Math.floor((now - crashDate.getTime()) / (1000 * 60 * 60)));
    }

    d.totalCrashes += count;
    if (hoursAgo <= 24) {
      d.crashesLast24h += count;
    }
    if (hoursAgo <= 168) {
      d.crashesLast7d += count;
    }

    if (crashDate && (!d.latestDate || crashDate.getTime() > d.latestDate.getTime())) {
      d.latestDate = crashDate;
      d.latestTimestamp = dateStr;
      d.latestHoursAgo = hoursAgo;
    } else if (!d.latestTimestamp && dateStr) {
      d.latestTimestamp = dateStr;
      d.latestHoursAgo = hoursAgo;
    }

    if (reason) {
      d.reasons.set(reason, (d.reasons.get(reason) || 0) + count);
    }

    d.crashEvents.push({ date: dateStr, reason, count, hoursAgo });
  }

  const rawLines = logText.split(/\r?\n/);

  // Regex Patterns based on FortiOS Knowledge Base
  const AGG_CRASH_RE = /^(?:\d+:\s+)?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+([a-zA-Z0-9_-]+)\s+previously\s+crashed\s+(\d+)\s+times(?:\.\s+The\s+(?:last|latest)\s+crash\s+was\s+at\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}))?/i;
  const CRASHED_IN_RE = /^(?:\d+:\s+)?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+([a-zA-Z0-9_-]+)(?:\s+<\d+>|\s+\d+)?\s+crashed\s+in(?:\s+([a-zA-Z0-9_.-]+))?/i;
  const WATCHDOG_RE = /^(?:\d+:\s+)?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+([a-zA-Z0-9_-]+)(?:\s+<\d+>|\s+\d+)?\s+watchdog\s+timeout/i;
  const SINGLE_LINE_CRASH_RE = /^(?:\d+:\s+)?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}),?\s*(?:<\d+>\s*)?application\s+([a-zA-Z0-9_-]+),?\s*(?:\*\*\*\s*)?signal\s+(\d+)(?:\s*\(([^)]+)\))?/i;
  const APP_LINE_RE = /^(?:\d+:\s+)?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?:<\d+>\s+)?application\s+([a-zA-Z0-9_-]+)/i;
  const SIG_LINE_RE = /^(?:\d+:\s+)?(?:(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+)?(?:<\d+>\s+)?(?:\*\*\*\s*)?signal\s+(\d+)(?:\s*\(([^)]+)\))?/i;

  let pendingApp = null;
  let pendingDate = null;
  let pendingLineIdx = -999;

  for (let i = 0; i < rawLines.length; i++) {
    const line = rawLines[i].trim();
    if (!line) continue;

    // Pattern 1: Aggregated crashes (e.g. httpsd previously crashed 14 times)
    const aggMatch = AGG_CRASH_RE.exec(line);
    if (aggMatch) {
      const date = aggMatch[1];
      const app = aggMatch[2];
      const count = parseInt(aggMatch[3], 10);
      const lastDate = aggMatch[4] || date;
      const sigKey = `agg_${app}_${count}_${lastDate}`;
      if (!seenSignatures.has(sigKey)) {
        seenSignatures.add(sigKey);
        recordDaemonCrash(app, lastDate, null, count);
      }
      continue;
    }

    // Pattern 2: Module-Specific Aborts (e.g. scanunit 29396 crashed in scanunit)
    const abortMatch = CRASHED_IN_RE.exec(line);
    if (abortMatch) {
      const date = abortMatch[1];
      const app = abortMatch[2];
      const sigKey = `abort_${app}_${date}`;
      if (!seenSignatures.has(sigKey)) {
        seenSignatures.add(sigKey);
        recordDaemonCrash(app, date, "Process Abort", 1);
      }
      continue;
    }

    // Pattern 3: Watchdog Timeout (e.g. ipsengine watchdog timeout)
    const wdMatch = WATCHDOG_RE.exec(line);
    if (wdMatch) {
      const date = wdMatch[1];
      const app = wdMatch[2];
      const sigKey = `wd_${app}_${date}`;
      if (!seenSignatures.has(sigKey)) {
        seenSignatures.add(sigKey);
        recordDaemonCrash(app, date, "Watchdog Timeout", 1);
      }
      continue;
    }

    // Pattern 4: Single-Line Application Crash
    const singleMatch = SINGLE_LINE_CRASH_RE.exec(line);
    if (singleMatch) {
      const date = singleMatch[1];
      const app = singleMatch[2];
      const sigNum = singleMatch[3];
      const sigDesc = singleMatch[4] || "";
      const reason = formatSignalReason(sigNum, sigDesc);
      const sigKey = `single_${app}_${date}_${sigNum}`;
      if (!seenSignatures.has(sigKey)) {
        seenSignatures.add(sigKey);
        recordDaemonCrash(app, date, reason, 1);
      }
      continue;
    }

    // Pattern 5: Multi-Line Standard Crash Context Merging
    // Line 1: application <app>
    const appMatch = APP_LINE_RE.exec(line);
    if (appMatch) {
      if (pendingApp && (i - pendingLineIdx <= 5)) {
        const prevKey = `pending_${pendingApp}_${pendingDate}`;
        if (!seenSignatures.has(prevKey)) {
          seenSignatures.add(prevKey);
          recordDaemonCrash(pendingApp, pendingDate, "Process Crash", 1);
        }
      }
      pendingDate = appMatch[1];
      pendingApp = appMatch[2];
      pendingLineIdx = i;
      continue;
    }

    // Line 2: signal <sigNum>
    const sigMatch = SIG_LINE_RE.exec(line);
    if (sigMatch && (sigMatch[2] !== undefined)) {
      const sigDate = sigMatch[1] || pendingDate;
      const sigNum = sigMatch[2];
      const sigDesc = sigMatch[3] || "";
      const reason = formatSignalReason(sigNum, sigDesc);
      const app = (pendingApp && (i - pendingLineIdx <= 5)) ? pendingApp : "system";
      const sigKey = `multi_${app}_${sigDate}_${sigNum}`;
      if (!seenSignatures.has(sigKey)) {
        seenSignatures.add(sigKey);
        recordDaemonCrash(app, sigDate, reason, 1);
      }
      pendingApp = null;
      pendingDate = null;
      pendingLineIdx = -999;
      continue;
    }
  }

  // Flush any dangling pendingApp at end of log
  if (pendingApp) {
    const prevKey = `pending_${pendingApp}_${pendingDate}`;
    if (!seenSignatures.has(prevKey)) {
      seenSignatures.add(prevKey);
      recordDaemonCrash(pendingApp, pendingDate, "Process Crash", 1);
    }
  }

  const daemonEntries = Array.from(daemons.values());

  if (daemonEntries.length === 0) {
    return makeFinding({
      id: "FGT-SYS-03",
      component: "Daemon Crash Log History",
      status: "PASS",
      findingText: "Crash log is clean: no daemon crash events recorded.",
      actionText: "",
      source: "cli",
      data: { crashes: [] }
    });
  }

  // Determine Primary Reason & Impact for each daemon
  for (const d of daemonEntries) {
    let bestReason = "Process Crash";
    let maxReasonCount = 0;
    for (const [r, count] of d.reasons.entries()) {
      if (count > maxReasonCount) {
        maxReasonCount = count;
        bestReason = r;
      }
    }
    d.primaryReason = bestReason;
    d.impact = DAEMON_IMPACT_MAP[d.app.toLowerCase()] || "";
  }

  // Severity Logic
  const hasCritical24h = daemonEntries.some(
    d => CRITICAL_CORE_DAEMONS.has(d.app.toLowerCase()) && d.crashesLast24h > 0
  );
  const hasRepeated7d = daemonEntries.some(d => d.crashesLast7d >= 3);
  const hasAny7d = daemonEntries.some(d => d.crashesLast7d > 0);

  let status = "PASS";
  if (hasCritical24h || hasRepeated7d) {
    status = "FAIL";
  } else if (hasAny7d) {
    status = "WARN";
  } else {
    status = "PASS";
  }

  if (status === "PASS") {
    return makeFinding({
      id: "FGT-SYS-03",
      component: "Daemon Crash Log History",
      status: "PASS",
      findingText: "Crash log is clean: no daemon crash events recorded in the last 7 days.",
      actionText: "",
      source: "cli",
      data: { crashes: daemonEntries }
    });
  }

  // Sort daemons by most recent date (descending), then by highest total crashes (descending)
  daemonEntries.sort((a, b) => {
    const timeA = a.latestDate ? a.latestDate.getTime() : 0;
    const timeB = b.latestDate ? b.latestDate.getTime() : 0;
    if (timeB !== timeA) return timeB - timeA;
    return b.totalCrashes - a.totalCrashes;
  });

  const bulletLines = daemonEntries.map(
    d => `  • [${d.app}] crashed ${d.totalCrashes} times (${d.primaryReason}) - Latest: ${d.latestTimestamp}`
  );

  const lines = [
    "Daemon process instability detected. The following crashes were recorded:",
    ...bulletLines
  ];

  const impactedDaemons = daemonEntries.filter(d => d.impact);
  if (impactedDaemons.length > 0) {
    lines.push("");
    lines.push("Impact Analysis:");
    for (const d of impactedDaemons) {
      lines.push(`  • ${d.app}: ${d.impact}`);
    }
  }

  const findingText = lines.join("\n");

  return makeFinding({
    id: "FGT-SYS-03",
    component: "Daemon Crash Log History",
    status,
    findingText,
    actionText: status === "FAIL"
      ? "Inspect crash log details ('diagnose debug crashlog read'), open a high-priority ticket with Fortinet TAC, and verify if a firmware update or memory leak patch is required for the unstable daemon(s)."
      : "Monitor process stability over upcoming operational cycles and open a support ticket if crash frequency increases.",
    source: "cli",
    data: { crashes: daemonEntries }
  });
}

/**
 * FGT-HA-01: FortiGate HA Clustering
 * MUST ONLY evaluate if the command header 'get system ha status' exists.
 * FAIL: HA Health Status != "OK", or any cluster member indicates out-of-sync.
 * PASS: HA Health is OK and all members are in-sync with identical checksums.
 */
function checkFgtHaStatus(text) {
  if (!hasCommand(text, "get system ha status") && !/HA\s+Health\s+Status/i.test(text)) {
    return null;
  }

  // Handle standalone mode gracefully if present
  const modeMatch = /Mode:\s*([A-Za-z0-9_-]+)/i.exec(text);
  if (modeMatch && modeMatch[1].toLowerCase() === "standalone") {
    return makeFinding(
      "FGT-HA-01",
      "FortiGate HA Clustering",
      "INFO",
      "Device is operating in Standalone mode (HA is not configured).",
      "",
      "cli"
    );
  }

  // Flexible regex handling multiple spaces, non-breaking spaces (\u00A0), and optional spacing before ':'
  const healthMatch = /HA\s+Health\s+Status\s*[:=]\s*([A-Za-z]+)/i.exec(text);
  const health = healthMatch ? healthMatch[1].trim() : null;

  const hasInSync = /\bin-sync\b/i.test(text);
  const hasOutOfSync = /\bout-of-sync\b/i.test(text);

  // Cluster is healthy if explicitly OK, or if members report in-sync without out-of-sync
  const isHealthy = (health && health.toLowerCase() === "ok") || (hasInSync && !hasOutOfSync);

  if (!isHealthy || hasOutOfSync) {
    let reason = "Cluster member out-of-sync detected";
    if (!hasInSync && !health) {
      reason = "No synchronized cluster members or health status identified in output";
    } else if (health && health.toLowerCase() !== "ok") {
      reason = `HA Health Status is "${health}"`;
    }

    return makeFinding(
      "FGT-HA-01",
      "FortiGate HA Clustering",
      "FAIL",
      `HA cluster desynchronization or failure: ${reason}${hasOutOfSync && health && health.toLowerCase() === "ok" ? " (members reporting out-of-sync)" : ""}.`,
      "Run 'diagnose sys ha checksum show' on each cluster node to isolate the mismatched configuration blocks, then re-sync cluster configuration.",
      "cli"
    );
  }

  return makeFinding(
    "FGT-HA-01",
    "FortiGate HA Clustering",
    "PASS",
    "HA cluster is operational and healthy: Health Status is OK and all cluster members report in-sync.",
    "",
    "cli"
  );
}

/**
 * FGT-FG-01: FortiGuard Sync
 * Triggers: diagnose autoupdate status
 * FAIL: FDN availability: unavailable or last successful sync > 24 hours ago.
 * Recommendation: "Check DNS and egress ports (UDP/TCP 8888, 443). Refer to Fortinet Community KB and update client if unresolved."
 * PASS: FDN available.
 */
function checkFgtFortiGuardSync(text) {
  if (!hasCommand(text, "diagnose autoupdate status") && !/FDN availability/i.test(text)) {
    return null;
  }

  const availMatch = /FDN availability:\s*([A-Za-z]+)/i.exec(text);
  const available = availMatch ? availMatch[1].toLowerCase() : null;

  const lastUpdateMatch =
    /Last update[^\n:]*:\s*([^\n]+)/i.exec(text) ||
    /Last successful[^\n:]*:\s*([^\n]+)/i.exec(text);

  if (available === "unavailable") {
    return makeFinding(
      "FGT-FG-01",
      "FortiGuard Sync",
      "FAIL",
      "FDN availability reported as 'unavailable' — FortiGate is unable to communicate with FortiGuard servers for signature/definition updates.",
      "Check DNS and egress ports (UDP/TCP 8888, 443). Refer to Fortinet Community KB and update client if unresolved.",
      "cli"
    );
  }

  if (lastUpdateMatch) {
    const rawDate = lastUpdateMatch[1].trim();
    const parsedDate = new Date(rawDate);
    if (!Number.isNaN(parsedDate.getTime())) {
      const ageHours = (Date.now() - parsedDate.getTime()) / 3600000;
      if (ageHours > THRESHOLDS.fdnStaleHours) {
        return makeFinding(
          "FGT-FG-01",
          "FortiGuard Sync",
          "FAIL",
          `Last successful FortiGuard sync was ${rawDate} (~${Math.round(ageHours)}h ago), exceeding the ${THRESHOLDS.fdnStaleHours}h freshness threshold.`,
          "Check DNS and egress ports (UDP/TCP 8888, 443). Refer to Fortinet Community KB and update client if unresolved.",
          "cli"
        );
      }
    }
  }

  if (available === "available" || available === "yes") {
    return makeFinding(
      "FGT-FG-01",
      "FortiGuard Sync",
      "PASS",
      "FortiGuard FDN connection is available and definition update synchronization is current.",
      "",
      "cli"
    );
  }

  return makeFinding(
    "FGT-FG-01",
    "FortiGuard Sync",
    "WARN",
    "diagnose autoupdate status output detected, but FDN availability status could not be conclusively validated.",
    "Verify FortiGuard connectivity manually via 'execute ping service.fortiguard.net'.",
    "cli"
  );
}

/**
 * FGT-IPSEC-01: FortiGate IPSec Tunnels (Advanced Phase 2 Inspection)
 * Commands: get vpn ipsec tunnel summary & diagnose vpn tunnel list
 */
function checkFgtIpsecTunnels(text) {
  const hasSummary = hasCommand(text, "get vpn ipsec tunnel summary") || /selectors\(total,up\):/i.test(text);
  const hasList = hasCommand(text, "diagnose vpn tunnel list") || /proxyid=/i.test(text);

  if (!hasSummary && !hasList) {
    return null;
  }

  const tunnelsMap = new Map();

  // 1. Parse Summary (Total vs Up)
  if (hasSummary) {
    const tunnelRe = /^'([^']+)'\s+([\d\.:]+)\s+selectors\(total,up\):\s*(\d+)\/(\d+)/gm;
    let m;
    while ((m = tunnelRe.exec(text)) !== null) {
      tunnelsMap.set(m[1], {
        name: m[1],
        peer: m[2],
        total: parseInt(m[3], 10),
        up: parseInt(m[4], 10),
        deadSelectors: []
      });
    }
  }

  // 2. Parse Detailed Tunnel List (sa=0 Dead Selectors)
  if (hasList) {
    const proxyRe = /proxyid=([^\s]+)[^\n]*?sa=0[^\n]*\r?\n\s*src:\s*([^\r\n]+)\r?\n\s*dst:\s*([^\r\n]+)/gi;
    let pm;
    while ((pm = proxyRe.exec(text)) !== null) {
      const tName = pm[1];
      // Cleanup "0:192.168.10.0/255.255.255.0:0" -> "192.168.10.0/255.255.255.0"
      const src = pm[2].replace(/^(?:0:)?/, "").replace(/:\d+$/, "").trim();
      const dst = pm[3].replace(/^(?:0:)?/, "").replace(/:\d+$/, "").trim();

      if (tunnelsMap.has(tName)) {
        tunnelsMap.get(tName).deadSelectors.push(`Local: ${src} -> Remote: ${dst}`);
      } else {
        // Found dead selector but no summary info (partial log snippet)
        tunnelsMap.set(tName, {
          name: tName,
          peer: "Unknown",
          total: 1,
          up: 0,
          deadSelectors: [`Local: ${src} -> Remote: ${dst}`]
        });
      }
    }
  }

  if (tunnelsMap.size === 0) return null;

  const tunnels = Array.from(tunnelsMap.values());
  const degraded = tunnels.filter(t => t.up === 0 || t.up < t.total || t.deadSelectors.length > 0);

  if (degraded.length) {
    const bullets = degraded.map(t => {
      let line = `  • Tunnel '${t.name}' (Peer: ${t.peer}) - Selectors: ${t.up}/${t.total} UP`;
      if (t.deadSelectors.length > 0) {
        line += `\n    - Dead Selectors Identified:\n` + t.deadSelectors.map(s => `      > ${s} (sa=0)`).join("\n");
      }
      return line;
    }).join("\n");

    const firstName = degraded[0].name;

    return makeFinding({
      id: "FGT-IPSEC-01",
      component: "FortiGate IPSec Tunnels",
      status: "FAIL",
      findingText: `IPSec tunnel degradation detected: ${degraded.length} of ${tunnels.length} tunnel(s) experiencing Phase 2 failures:\n${bullets}`,
      actionText: "Verify Phase 2 subnet parameters and NAT-T matching. To forcefully re-negotiate stuck IPsec selectors, clear the specific IKE gateway and flush the tunnel cache. To review tunnel traffic volume (Rx/Tx KB) and isolate idle tunnels, run 'get vpn ipsec tunnel details' or use the GUI IPsec Monitor.",
      remediationCli: `diagnose vpn ike gateway clear name ${firstName}\ndiagnose vpn tunnel flush ${firstName}`,
      source: "cli",
      data: { degradedCount: degraded.length }
    });
  }

  const allNames = tunnels.map(t => t.name).join(", ");
  return makeFinding({
    id: "FGT-IPSEC-01",
    component: "FortiGate IPSec Tunnels",
    status: "PASS",
    findingText: `All ${tunnels.length} IPSec VPN tunnel(s) are fully UP with all Phase 2 selectors active (${allNames}).`,
    actionText: "",
    remediationCli: "",
    source: "cli",
    data: { degradedCount: 0 }
  });
}

/**
 * FGT-SDWAN-01: FortiGate SD-WAN SLA
 * Triggers: diagnose sys sdwan health-check
 * Parse each member interface, state (alive/dead), packet-loss, latency.
 * FAIL: Any member state != alive.
 * WARN: Packet-loss > 0.000% or latency > 50ms.
 * PASS: All SLA links alive with 0.000% packet loss.
 */
function checkFgtSdwanSla(text) {
  if (
    !hasCommand(text, "diagnose sys sdwan health-check") &&
    !hasCommand(text, "sdwan health-check") &&
    !/packet-loss/i.test(text)
  ) {
    return null;
  }

  const members = [];
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const intfM = /(?:interface|member|link)[:\s]+([a-zA-Z0-9_.-]+)/i.exec(line);
    const stateM = /state[:(]?\s*(alive|dead)/i.exec(line);
    const lossM = /(?:packet-loss|loss)[:(]?\s*([0-9.]+)%/i.exec(line);
    const latM = /(?:latency|rtt)[:(]?\s*([0-9.]+)\s*ms/i.exec(line);

    if (stateM || (lossM && latM)) {
      members.push({
        interface: intfM ? intfM[1] : `member-${members.length + 1}`,
        state: stateM ? stateM[1].toLowerCase() : (lossM && parseFloat(lossM[1]) < 100 ? "alive" : "dead"),
        loss: lossM ? parseFloat(lossM[1]) : 0,
        latency: latM ? parseFloat(latM[1]) : 0
      });
    }
  }

  if (!members.length) {
    const stateMatches = [...text.matchAll(/state[:(]\s*(alive|dead)\)?/gi)].map((m) => m[1].toLowerCase());
    const lossMatches = [...text.matchAll(/packet-loss[:(]\s*([0-9.]+)%\)?/gi)].map((m) => parseFloat(m[1]));
    const latencyMatches = [...text.matchAll(/latency[:(]\s*([0-9.]+)\s*ms\)?/gi)].map((m) => parseFloat(m[1]));
    const count = Math.max(stateMatches.length, lossMatches.length, latencyMatches.length);
    for (let i = 0; i < count; i++) {
      members.push({
        interface: `link-${i + 1}`,
        state: stateMatches[i] || "alive",
        loss: lossMatches[i] !== undefined ? lossMatches[i] : 0,
        latency: latencyMatches[i] !== undefined ? latencyMatches[i] : 0
      });
    }
  }

  if (!members.length) {
    return null;
  }

  const deadMembers = members.filter((m) => m.state === "dead");
  const degradedMembers = members.filter((m) => m.state === "alive" && (m.loss > 0 || m.latency > THRESHOLDS.sdwanLatencyWarnMs));

  const memberBullets = members
    .map((m) => `  • Member '${m.interface}': State = ${m.state}, Packet Loss = ${m.loss}%, Latency = ${m.latency}ms`)
    .join("\n");

  const rootCause = "Packet loss (>0%) or high latency (>50ms) violates the SD-WAN Performance SLA threshold, triggering failovers or degraded voice/video sessions.";
  const healthyBaseline = "State = alive, Packet Loss = 0.000%, Latency <= 50ms across all SLA members.";
  const triageAction = "Inspect underlying ISP gateway and physical carrier link. Review live health-check probes: diagnose sys sdwan health-check status and diagnose sys sdwan member.";

  if (deadMembers.length > 0) {
    return makeFinding(
      "FGT-SDWAN-01",
      "FortiGate SD-WAN SLA",
      "FAIL",
      `SD-WAN SLA failure: ${deadMembers.length} member interface(s) reporting state 'dead':\n${memberBullets}\n\nRoot Cause & Meaning: ${rootCause}\nHealthy Baseline: ${healthyBaseline}`,
      triageAction,
      "cli"
    );
  }

  if (degradedMembers.length > 0) {
    return makeFinding(
      "FGT-SDWAN-01",
      "FortiGate SD-WAN SLA",
      "WARN",
      `SD-WAN SLA degradation: ${degradedMembers.length} member link(s) exceeding SLA thresholds:\n${memberBullets}\n\nRoot Cause & Meaning: ${rootCause}\nHealthy Baseline: ${healthyBaseline}`,
      triageAction,
      "cli"
    );
  }

  return makeFinding(
    "FGT-SDWAN-01",
    "FortiGate SD-WAN SLA",
    "PASS",
    `All SD-WAN health-check member links meet SLA requirements:\n${memberBullets}\n\nHealthy Baseline: ${healthyBaseline}`,
    "",
    "cli"
  );
}

/**
 * FGT-FEED-01: FortiGate Threat Feeds
 * Trigger: When get system external-resource is detected in the input.
 * Parsing: Match all feed headers matching == [  ] or name: .
 * Output PASS with count (e.g., "8 external threat feed resources configured and active").
 * WARN if command output is empty or indicates sync failure.
 */
function cleanFeedIdentifier(raw) {
  if (!raw || typeof raw !== "string") return "";
  let s = raw.trim().replace(/^["'\s:=]+|["'\s:=]+$/g, "").trim();
  s = s.replace(/[:\s]+$/, "");
  const m = /\b(?:FGT-[A-Za-z0-9_-]+|[A-Z0-9]+(?:-[A-Z0-9]+)*)\b/i.exec(s);
  return m ? m[0] : s;
}

function checkFgtThreatFeeds(text, tokenizer = null) {
  const hasExtResSection = tokenizer ? !!tokenizer.getSection("system external-resource") : false;
  const hasExtResText = /external[\s_-]*resource|threat[\s_-]*feed|\bFGT-FEED/i.test(text);
  if (!hasExtResSection && !hasCommand(text, "get system external-resource") && !hasExtResText) {
    return null;
  }

  const feeds = [];

  if (tokenizer && tokenizer.getSection("system external-resource")) {
    const entries = tokenizer.getEntries("system external-resource");
    for (const [key, entry] of Object.entries(entries)) {
      const feedName = cleanFeedIdentifier(entry.name || entry._origKey || key);
      const props = entry.properties || {};
      const status = (props["status"] || "enable").toLowerCase();
      feeds.push({
        name: feedName,
        body: JSON.stringify(props),
        status: status,
        isDisabled: status.includes("disable"),
        hasError: false
      });
    }
  }

  if (!feeds.length && text) {
    const secMatch = /(?:config|show)\s+system\s+external-resource([\s\S]*?)(?:^end|\n\s*end)/im.exec(text);
    if (secMatch) {
      const blockRe = /edit\s+(?:"([^"]+)"|(\S+))([\s\S]*?)next/gi;
      let bm;
      while ((bm = blockRe.exec(secMatch[1])) !== null) {
        const feedName = cleanFeedIdentifier(bm[1] || bm[2]);
        const blockBody = bm[3] || "";
        const statusMatch = /set\s+status\s+(\S+)/i.exec(blockBody);
        const status = statusMatch ? statusMatch[1].toLowerCase() : "enable";
        feeds.push({
          name: feedName,
          body: blockBody,
          status: status,
          isDisabled: status.includes("disable"),
          hasError: false
        });
      }
    }
  }

  if (!feeds.length && text) {
    const isLiveCmd = hasCommand(text, "get system external-resource");
    const targetCliText = isLiveCmd ? extractCommandOutput(text, "get system external-resource") : (hasExtResSection ? "" : text);

    if (targetCliText) {
      const headerRe = /==\s*\[\s*(.+?)\s*\]([\s\S]*?)(?=(?:==\s*\[)|(?:#\s*[a-z])|(?:\n\s*\n\s*[A-Z])|$)/gi;
      let hm;
      while ((hm = headerRe.exec(targetCliText)) !== null) {
        const feedName = cleanFeedIdentifier(hm[1]);
        if (feedName && !/^(?:onboard|disk\d*|port\d+|mgmt\d*|vlan\d*|wan\d*|internal\d*|loopback\d*|ssl\.\w+|dmz\d*|ha|sync)$/i.test(feedName)) {
          feeds.push({
            name: feedName,
            body: hm[2].trim(),
          });
        }
      }

      if (!feeds.length) {
        const nameRe = /(?:^|\s|,|;)(?:name|feed|external[\s_-]*resource|resource)\s*[:=\s]\s*["']?(\b(?:FGT-[A-Za-z0-9_-]+|[A-Z0-9]+(?:-[A-Z0-9]+)*)\b)/gim;
        const nameMatches = [...targetCliText.matchAll(nameRe)];
        for (let i = 0; i < nameMatches.length; i++) {
          const feedName = cleanFeedIdentifier(nameMatches[i][1]);
          if (feedName && !/^(?:enable|disable|true|false|status|get|system|type|category|onboard|port\d+|disk\d*)$/i.test(feedName)) {
            const start = nameMatches[i].index;
            const end = i + 1 < nameMatches.length ? nameMatches[i + 1].index : targetCliText.length;
            feeds.push({
              name: feedName,
              body: targetCliText.slice(start, end).trim(),
            });
          }
        }
      }

      if (!feeds.length) {
        const standaloneMatches = [...targetCliText.matchAll(/\b(FGT-FEED-[A-Za-z0-9_-]+)\b/gi)];
        for (const sm of standaloneMatches) {
          const feedName = cleanFeedIdentifier(sm[1]);
          if (feedName && !feeds.some(f => f.name === feedName)) {
            feeds.push({
              name: feedName,
              body: targetCliText,
              status: "enable",
              isDisabled: false,
              hasError: false
            });
          }
        }
      }
    }
  }

  const src = (tokenizer && tokenizer.getSection("system external-resource")) ? "conf" : "cli";

  if (!feeds.length) {
    return makeFinding({
      id: "FGT-FEED-01",
      component: "FortiGate Threat Feeds",
      status: "WARN",
      findingText: "get system external-resource output is empty — no external threat feed resources configured on the firewall.",
      actionText: "Check connectivity to external resource URLs and verify refreshing status.",
      source: src,
      data: { count: 0, feeds: "" }
    });
  }

  const problems = [];
  for (const feed of feeds) {
    const statusMatch = feed.status ? null : /status\s*:\s*(\S+)/i.exec(feed.body || "");
    const status = feed.status || (statusMatch ? statusMatch[1].toLowerCase() : "unknown");
    const hasError = feed.hasError || /(unreachable|error|failed|timeout|failure)/i.test(feed.body || "");
    const isDisabled = feed.isDisabled !== undefined ? feed.isDisabled : (status && !/enable|active/.test(status));

    if (isDisabled || hasError) {
      problems.push({
        name: feed.name,
        status: status,
        details: hasError ? "sync failure / unreachable" : (isDisabled ? "disabled" : "inactive")
      });
    }
  }

  const feedNamesStr = feeds.map((f) => f.name).join(", ");

  if (problems.length > 0) {
    const bullets = problems
      .map(p => `  • Feed '${p.name}': Status = ${p.status}, Error = ${p.details}`)
      .join("\n");
    return makeFinding({
      id: "FGT-FEED-01",
      component: "FortiGate Threat Feeds",
      status: "WARN",
      findingText: `${problems.length} of ${feeds.length} external threat feed(s) indicate sync failure or inactive status:\n${bullets}`,
      actionText: "Check connectivity to external resource URLs and verify refreshing status.",
      source: src,
      data: { count: feeds.length, feeds: feedNamesStr }
    });
  }

  const activeBullets = feeds
    .map(f => `  • Feed '${f.name}': Active & Synchronized`)
    .join("\n");

  return makeFinding({
    id: "FGT-FEED-01",
    component: "FortiGate Threat Feeds",
    status: "PASS",
    findingText: `${feeds.length} external threat feed resources configured and active (${feedNamesStr}):\n${activeBullets}`,
    actionText: "",
    source: src,
    data: { count: feeds.length, feeds: feedNamesStr }
  });
}

/**
 * SEC-INTF-01: Administrative Access on WAN
 * Supported in both Static Config and Live CLI (show system interface | grep -i allowaccess).
 * Inspect interface blocks where set role wan or alias/name contains "wan"/"isp"/"internet".
 * FAIL: If set allowaccess includes https, ssh, http, or telnet.
 * Action: "Disable administrative access on external interface and document in client misconfiguration tracker."
 * PASS: Management access restricted to internal/dedicated management interfaces.
 */
function checkSecWanAdminAccess(text, tokenizer = null) {
  const hasIntfCmd =
    hasCommand(text, "system interface") ||
    /show system interface/i.test(text) ||
    /config system interface/i.test(text) ||
    /allowaccess/i.test(text);

  if (!hasIntfCmd) return null;

  const entries = [];

  if (tokenizer) {
    const intfSection = tokenizer.getSection("system interface");
    if (intfSection && Object.keys(intfSection.entries).length > 0) {
      for (const [name, entry] of Object.entries(intfSection.entries)) {
        entries.push({
          name,
          role: (entry.properties["role"] || "").toLowerCase(),
          alias: (entry.properties["alias"] || "").toLowerCase(),
          allowaccess: (entry.properties["allowaccess"] || "").toLowerCase(),
          source: "conf",
        });
      }
    }
  }

  if (!entries.length) {
    const blockRe = /edit\s+(?:"([^"]+)"|(\S+))([\s\S]*?)next/gi;
    let m;
    while ((m = blockRe.exec(text)) !== null) {
      const name = m[1] || m[2];
      const body = m[3];
      const allowMatch = /set\s+allowaccess\s+([^\n]+)/i.exec(body);
      if (!allowMatch) continue;

      const roleMatch = /set\s+role\s+(\S+)/i.exec(body);
      const aliasMatch = /set\s+alias\s+(?:"([^"]+)"|(\S+))/i.exec(body);

      entries.push({
        name,
        role: roleMatch ? roleMatch[1].toLowerCase() : "",
        alias: aliasMatch ? (aliasMatch[1] || aliasMatch[2]).toLowerCase() : "",
        allowaccess: allowMatch[1].toLowerCase(),
        source: "cli",
      });
    }
  }

  if (!entries.length) return null;

  const offendingInterfaces = [];

  for (const intf of entries) {
    const isExternal =
      intf.role === "wan" ||
      /\b(wan|isp|internet)\b/i.test(intf.alias) ||
      /\b(wan|isp|internet)\b/i.test(intf.name) ||
      intf.name.toLowerCase().startsWith("wan");

    if (isExternal) {
      const exposedProtocols = [];
      if (/\bhttps\b/i.test(intf.allowaccess)) exposedProtocols.push("HTTPS");
      if (/\bssh\b/i.test(intf.allowaccess)) exposedProtocols.push("SSH");
      if (/\bhttp\b/i.test(intf.allowaccess)) exposedProtocols.push("HTTP");
      if (/\btelnet\b/i.test(intf.allowaccess)) exposedProtocols.push("TELNET");

      if (exposedProtocols.length > 0) {
        offendingInterfaces.push(
          `${intf.name}${intf.alias ? ` ("${intf.alias}")` : ""}: [${exposedProtocols.join(", ")}]`
        );
      }
    }
  }

  const primarySource = entries.some((e) => e.source === "cli") ? "cli" : "conf";

  if (offendingInterfaces.length > 0) {
    return makeFinding(
      "SEC-INTF-01",
      "WAN Administrative Access",
      "FAIL",
      `Administrative access exposed on external/WAN interface(s): ${offendingInterfaces.join("; ")}.`,
      "Disable administrative access on external interface and document in client misconfiguration tracker.",
      primarySource
    );
  }

  return makeFinding(
    "SEC-INTF-01",
    "WAN Administrative Access",
    "PASS",
    "Management access (HTTPS/SSH/HTTP/Telnet) is restricted to internal/dedicated management interfaces. External WAN interfaces are secured.",
    "",
    primarySource
  );
}

function formatAccountList(accounts, limit = 5) {
  if (!accounts || accounts.length === 0) return "";
  if (accounts.length <= limit) {
    return accounts.join(", ");
  }
  const displayed = accounts.slice(0, limit).join(", ");
  const remaining = accounts.length - limit;
  return `${displayed} (+${remaining} others)`;
}

/**
 * SEC-USER-01: User Authentication & MFA
 * Enabled in BOTH Static Config (.conf) and Live CLI Mode (show user local / config user local).
 * Audits both local password accounts and domain LDAP accounts in config user local.
 * Checks for global SAML configuration (config user saml or set type saml).
 * Severity:
 * - FAIL: If any local password account lacks MFA OR > 5 LDAP accounts lack MFA.
 * - WARN: If password accounts have MFA, but 1-5 LDAP accounts lack MFA tokens.
 * - PASS: When 100% of accounts have two-factor enabled, or global SAML is active.
 */
function checkSecLocalUsersMfa(text, tokenizer = null) {
  const hasUserCmd =
    hasCommand(text, "show user local") ||
    hasCommand(text, "config user local") ||
    (tokenizer && !!tokenizer.getSection("user local")) ||
    /user\s+local/i.test(text);

  if (!hasUserCmd) return null;

  const users = [];

  if (tokenizer) {
    const userSection = tokenizer.getSection("user local");
    if (userSection && Object.keys(userSection.entries).length > 0) {
      for (const [name, entry] of Object.entries(userSection.entries)) {
        users.push({
          name,
          type: (entry.properties["type"] || "password").replace(/^"+|"+$/g, "").toLowerCase(),
          twoFactor: entry.properties["two-factor"] ? entry.properties["two-factor"].replace(/^"+|"+$/g, "").toLowerCase() : null,
          source: "conf",
        });
      }
    }
  }

  if (!users.length) {
    const sectionMatch =
      /(?:show|config)\s+user\s+local([\s\S]*?)(?:^end|\n\s*end|#\s*[a-z]|$)/im.exec(text) ||
      /user\s+local([\s\S]*?)(?:^end|\n\s*end|#\s*[a-z]|$)/im.exec(text);

    const blockText = sectionMatch ? sectionMatch[1] : text;
    const blockRe = /edit\s+(?:"([^"]+)"|(\S+))([\s\S]*?)next/gi;
    let m;
    while ((m = blockRe.exec(blockText)) !== null) {
      const name = m[1] || m[2];
      const body = m[3];
      const typeMatch = /set\s+type\s+(\S+)/i.exec(body);
      const tfMatch = /set\s+two-factor\s+(\S+)/i.exec(body);
      users.push({
        name,
        type: typeMatch ? typeMatch[1].replace(/^"+|"+$/g, "").toLowerCase() : "password",
        twoFactor: tfMatch ? tfMatch[1].replace(/^"+|"+$/g, "").toLowerCase() : null,
        source: "cli",
      });
    }
  }

  if (!users.length) return null;

  const primarySource = users.some((u) => u.source === "cli") ? "cli" : "conf";

  // Check for global SAML configuration
  const hasSamlSection = tokenizer
    ? (!!tokenizer.getSection("user saml") || !!tokenizer.getSection("system saml"))
    : /(?:config|show)\s+(?:user|system)\s+saml/i.test(text);
  const hasSamlType = /set\s+type\s+saml/i.test(text);
  const hasGlobalSaml = hasSamlSection || hasSamlType;

  const insecurePasswordAccounts = [];
  const singleFactorLdapAccounts = [];
  const compliantMfaAccounts = [];

  for (const user of users) {
    const type = user.type || "password";
    const hasMfa = !!(
      user.twoFactor &&
      user.twoFactor !== "disable" &&
      user.twoFactor !== "none"
    );

    if (hasMfa) {
      compliantMfaAccounts.push(user.name);
    } else {
      if (type === "password" || type === "local") {
        insecurePasswordAccounts.push(user.name);
      } else if (type === "ldap") {
        singleFactorLdapAccounts.push(user.name);
      }
    }
  }

  const remCli = [
    "config user local",
    '    edit "<username>"',
    "        set two-factor fortitoken",
    '        set fortitoken "<token-serial>"',
    '        set email-to "<user@domain.com>"',
    "    next",
    "end"
  ].join("\n");

  const actionText =
    "Enforce FortiToken Mobile or Email MFA on all remaining LDAP users, audit and remove obsolete test/admin accounts (e.g., 'test1', 'iteam_VPN'), or migrate SSL-VPN authentication to SAML (Microsoft Entra ID / Okta) with centralized Conditional Access MFA.";

  // Global SAML enforced
  if (hasGlobalSaml && insecurePasswordAccounts.length === 0) {
    return makeFinding({
      id: "SEC-USER-01",
      component: "User Authentication & MFA",
      status: "PASS",
      category: "SecOps Operational",
      source: primarySource,
      data: { isSaml: true, insecurePasswordAccounts, singleFactorLdapAccounts, compliantMfaAccounts },
      findingText: "Corporate Multi-Factor Authentication is globally enforced via SAML Identity Provider (Microsoft Entra ID / Okta). Centralized Conditional Access MFA is active.",
      actionText: "",
      remediationCli: remCli,
    });
  }

  // 100% compliant accounts
  if (insecurePasswordAccounts.length === 0 && singleFactorLdapAccounts.length === 0) {
    return makeFinding({
      id: "SEC-USER-01",
      component: "User Authentication & MFA",
      status: "PASS",
      category: "SecOps Operational",
      source: primarySource,
      data: { isSaml: false, insecurePasswordAccounts, singleFactorLdapAccounts, compliantMfaAccounts },
      findingText: `All ${compliantMfaAccounts.length} defined local and domain user account(s) have Multi-Factor Authentication (two-factor) enabled.`,
      actionText: "",
      remediationCli: remCli,
    });
  }

  // Severity decision: FAIL if any local password lacks MFA OR > 5 LDAP accounts lack MFA
  const isFail = insecurePasswordAccounts.length > 0 || singleFactorLdapAccounts.length > 5;
  const header = isFail
    ? "Critical Incomplete MFA Coverage on FortiGate:"
    : "Incomplete MFA Coverage on FortiGate:";

  const lines = [header];
  if (insecurePasswordAccounts.length > 0) {
    lines.push(
      `  • Insecure Local Password Accounts (${insecurePasswordAccounts.length}): ${formatAccountList(insecurePasswordAccounts)}`
    );
  }
  if (singleFactorLdapAccounts.length > 0) {
    lines.push(
      `  • Single-Factor LDAP Accounts (${singleFactorLdapAccounts.length}): ${formatAccountList(singleFactorLdapAccounts)}`
    );
  }
  if (compliantMfaAccounts.length > 0) {
    lines.push(
      `  • Compliant MFA Accounts (${compliantMfaAccounts.length}): ${formatAccountList(compliantMfaAccounts)}`
    );
  }

  lines.push("");
  if (singleFactorLdapAccounts.length > 0) {
    lines.push(
      "Impact: Single-factor LDAP users authenticate via standard domain credentials only, bypassing multi-factor verification on the SSL-VPN gateway."
    );
  } else {
    lines.push(
      "Impact: Local password accounts authenticate via single-factor static credentials only, vulnerable to brute-force attacks and compromised credentials."
    );
  }

  return makeFinding(
    "SEC-USER-01",
    "User Authentication & MFA",
    isFail ? "FAIL" : "WARN",
    lines.join("\n"),
    actionText,
    remCli,
    "SecOps Operational",
    primarySource
  );
}

/**
 * FGT-BAN-01: FortiGate Banned / Quarantine IPs
 * Triggers: diagnose user ban list
 * WARN / SOC ACTION: If table contains active banned IPs (src-ip-addr), extract count and IP list.
 * Action: "Submit Pull Request to block these IPs globally across all customer environments."
 * PASS: No active IP bans.
 */
function checkFgtBanList(text) {
  const hasBanCmd =
    hasCommand(text, "diagnose user ban list") ||
    /diagnose user ban list/i.test(text);

  if (!hasBanCmd && !/ban list/i.test(text)) return null;

  const headingMatch = /diagnose user ban list[^\n]*\n([\s\S]*?)(?:\n\s*\n|#\s*$|$)/i.exec(text);
  const block = headingMatch ? headingMatch[1] : text;

  const ipRe = /\b(?:src-ip-addr\s*[:=]\s*)?((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3})\b/g;
  const matches = [...block.matchAll(ipRe)].map((m) => m[1]);
  const uniqueIps = [...new Set(matches.filter((ip) => ip !== "0.0.0.0" && ip !== "255.255.255.255"))];

  if (uniqueIps.length > 0) {
    return makeFinding(
      "FGT-BAN-01",
      "FortiGate Banned IPs",
      "WARN",
      `${uniqueIps.length} active banned/quarantined IP(s) detected in the ban table: ${uniqueIps.join(", ")}.`,
      "Submit Pull Request to block these IPs globally across all customer environments.",
      "cli"
    );
  }

  return makeFinding(
    "FGT-BAN-01",
    "FortiGate Banned IPs",
    "PASS",
    "No active IP bans found in quarantine table (0 banned source IPs).",
    "",
    "cli"
  );
}

/**
 * FGT-LOG-01: FortiGate Analyzer Connectivity
 * Triggers: diagnose test application miglogd 6
 * PASS: faz= counter is active and incrementing (> 0).
 */
function checkFgtMiglogd(text) {
  if (!hasCommand(text, "miglogd")) return null;

  const fazMatch = /faz\s*=\s*(\d+)/i.exec(text);

  if (!fazMatch) {
    return makeFinding(
      "FGT-LOG-01",
      "FortiGate Log Delivery",
      "WARN",
      "miglogd diagnostic output detected, but 'faz=' counter was not found.",
      "Verify FortiAnalyzer destination configuration ('config log fortianalyzer setting') and verify OFTP certificate trust.",
      "cli"
    );
  }

  const count = parseInt(fazMatch[1], 10);
  if (count > 0) {
    return makeFinding(
      "FGT-LOG-01",
      "FortiGate Log Delivery",
      "PASS",
      `miglogd reports active log transmission to FortiAnalyzer (faz=${count} messages processed/sent).`,
      "",
      "cli"
    );
  }

  return makeFinding(
    "FGT-LOG-01",
    "FortiGate Log Delivery",
    "WARN",
    "miglogd reports faz=0 — no logs are currently being forwarded to the FortiAnalyzer.",
    "Verify network reachability to FortiAnalyzer and confirm firewall policy logging ('set logtraffic all') is enabled.",
    "cli"
  );
}

/**
 * FAZ-STOR-01: FortiAnalyzer Storage Threshold
 * Triggers: diagnose system print df & diagnose log device
 * Parse /Storage, /var, and System Storage Summary: Use%.
 * FAIL: Use% >= 75%. Action: "Alert! Disk usage reached 75%. Send email to client requesting additional storage disk."
 * WARN: Use% between 70% and 74%.
 * PASS: Use% < 70%.
 */
function checkFazStorage(text) {
  if (!isFazOutput(text)) return null;

  const summaryMatch = /System Storage Summary:[\s\S]*?Use%\s*\n[^\n]*?(\d+(?:\.\d+)?)%/i.exec(text);
  const dfLines = [...text.matchAll(/^(\S+)\s+[\d,]+\s+[\d,]+\s+[\d,]+\s+(\d+)%\s+(\/\S*)$/gm)];

  if (!summaryMatch && !dfLines.length) return null;

  let worst = null;
  if (summaryMatch) {
    worst = { mount: "System Storage Summary", pct: parseFloat(summaryMatch[1]) };
  }

  for (const dl of dfLines) {
    const pct = parseInt(dl[2], 10);
    const mount = dl[3];
    if (["/Storage", "/var", "/drive0"].includes(mount)) {
      if (!worst || pct > worst.pct) {
        worst = { mount, pct };
      }
    }
  }

  if (!worst) return null;

  if (worst.pct >= THRESHOLDS.fazStorageFail) {
    return makeFinding(
      "FAZ-STOR-01",
      "FortiAnalyzer Storage",
      "FAIL",
      `Critical disk utilization on ${worst.mount}: ${worst.pct}% used (>= ${THRESHOLDS.fazStorageFail}% threshold).`,
      "Alert! Disk usage reached 75%. Send email to client requesting additional storage disk.",
      "cli"
    );
  }

  if (worst.pct >= THRESHOLDS.fazStorageWarn) {
    return makeFinding(
      "FAZ-STOR-01",
      "FortiAnalyzer Storage",
      "WARN",
      `Elevated disk utilization on ${worst.mount}: ${worst.pct}% used (warning threshold: 70%-74%).`,
      "Review log retention policy / quotas and prepare storage expansion plan before disk reaches 75%.",
      "cli"
    );
  }

  return makeFinding(
    "FAZ-STOR-01",
    "FortiAnalyzer Storage",
    "PASS",
    `Healthy disk utilization on ${worst.mount}: ${worst.pct}% used (< ${THRESHOLDS.fazStorageWarn}% threshold).`,
    "",
    "cli"
  );
}

/**
 * FAZ-CONN-01: FortiAnalyzer Active Devices
 * Triggers: diagnose test application oftpd 3
 * Parse active connected devices from oftpd table (DEVICE, HOSTNAME, IP, IDLETIME).
 * PASS: All managed firewalls active with low idle times (< 60s).
 */
function checkFazActiveDevices(text) {
  if (!isFazOutput(text) || !hasCommand(text, "oftpd")) return null;

  const rows = [];
  const lines = text.split("\n");

  for (const line of lines) {
    if (!/^\s*\d+\s+\S+/.test(line)) continue;
    const ipMatch = /\d{1,3}(?:\.\d{1,3}){3}/.exec(line);
    if (!ipMatch) continue;
    const ip = ipMatch[0];

    const rowStart = /^\s*(\d+)\s+(\S+)/.exec(line);
    if (!rowStart) continue;
    const device = rowStart[2];

    const timeTokens = [...line.matchAll(/\b(?:\d+d|\d+h|\d+m|\d+s)+\b/gi)].map((mm) => mm[0]);
    let uptime = null;
    let idletime = null;
    if (timeTokens.length >= 2) {
      uptime = timeTokens[timeTokens.length - 2];
      idletime = timeTokens[timeTokens.length - 1];
    } else if (timeTokens.length === 1) {
      idletime = timeTokens[0];
    }

    const hostMatch = new RegExp("(\\S+)\\s+" + ip.replace(/\./g, "\\.")).exec(line);
    const hostname = hostMatch ? hostMatch[1] : "unknown";

    rows.push({ device, hostname, ip, uptime, idletime });
  }

  if (!rows.length) return null;

  const idleFlags = [];
  for (const r of rows) {
    const idleSec = durationToSeconds(r.idletime);
    if (idleSec !== null && idleSec >= THRESHOLDS.fazIdleWarnSeconds) {
      idleFlags.push(`${r.hostname} (${r.device}) idle ${secondsToHuman(idleSec)}`);
    }
  }

  const deviceListMatch = /--- There are currently (\d+) devices\/vdoms managed ---/i.exec(text);
  const expectedCount = deviceListMatch ? parseInt(deviceListMatch[1], 10) : null;

  const summary = `${rows.length} managed firewall(s) connected via OFTP: ${rows
    .map((r) => `${r.hostname} (idle: ${r.idletime || "0s"})`)
    .join(", ")}.`;

  if (idleFlags.length) {
    return makeFinding(
      "FAZ-CONN-01",
      "FortiAnalyzer Device Connectivity",
      "WARN",
      `${summary} High idle time (>= 60s) detected on: ${idleFlags.join("; ")}.`,
      "Inspect network stability and firewall miglogd process for the affected units to prevent disconnected logging sessions.",
      "cli"
    );
  }

  if (expectedCount !== null && rows.length < expectedCount) {
    return makeFinding(
      "FAZ-CONN-01",
      "FortiAnalyzer Device Connectivity",
      "WARN",
      `${expectedCount} devices managed in DVM, but only ${rows.length} active sessions present in OFTP table.`,
      "Identify disconnected FortiGate units and verify TCP port 514 / OFTP SSL connectivity.",
      "cli"
    );
  }

  return makeFinding(
    "FAZ-CONN-01",
    "FortiAnalyzer Device Connectivity",
    "PASS",
    `All ${rows.length} managed firewalls active with low idle times (< 60s). Log streaming healthy.`,
    "",
    "cli"
  );
}

/**
 * FAZ-SYS-01: FortiAnalyzer System Performance & HA
 * Triggers: get system performance & get system status & get system ha
 * Evaluate CPU, Memory, License Status (Valid), and HA Mode.
 */
function checkFazSysPerformanceHa(text) {
  if (!isFazOutput(text)) return null;

  const cpuMatch = /CPU:\s*\n\s*Used:\s*([\d.]+)%/i.exec(text);
  const memMatch = /Used \(Excluding Swap\):\s*[\d,]+\s*KB\s*([\d.]+)%/i.exec(text);
  const licenseMatch = /License Status\s*:\s*([A-Za-z]+)/i.exec(text);
  const haModeMatch = /HA Mode\s*:\s*([A-Za-z]+)/i.exec(text);

  if (!cpuMatch && !memMatch && !licenseMatch && !haModeMatch) {
    return null;
  }

  const cpu = cpuMatch ? parseFloat(cpuMatch[1]) : null;
  const mem = memMatch ? parseFloat(memMatch[1]) : null;
  const license = licenseMatch ? licenseMatch[1].trim() : "Valid";
  const haMode = haModeMatch ? haModeMatch[1].trim() : "Standalone";

  const isLicInvalid = license.toLowerCase() !== "valid";
  const isPerfFail =
    (cpu !== null && cpu > THRESHOLDS.fazCpuFail) ||
    (mem !== null && mem > THRESHOLDS.fazMemFail);

  if (isLicInvalid) {
    return makeFinding(
      "FAZ-SYS-01",
      "FortiAnalyzer System & HA",
      "FAIL",
      `FortiAnalyzer License Status is '${license}' (Expected: Valid). HA Mode: ${haMode}.`,
      "Renew or re-register FortiAnalyzer license entitlement in FortiCare support portal immediately.",
      "cli"
    );
  }

  if (isPerfFail) {
    return makeFinding(
      "FAZ-SYS-01",
      "FortiAnalyzer System & HA",
      "FAIL",
      `High resource utilization: CPU ${cpu || 0}% used, Memory ${mem || 0}% used (License: Valid, HA: ${haMode}).`,
      "Examine active report compilation, SQL queries, or log indexing load; consider VM memory/vCPU expansion.",
      "cli"
    );
  }

  return makeFinding(
    "FAZ-SYS-01",
    "FortiAnalyzer System & HA",
    "PASS",
    `FortiAnalyzer operating normally: CPU ${cpu || 0}%, Memory ${mem || 0}%, License: Valid, HA Mode: ${haMode}.`,
    "",
    "cli"
  );
}

/**
 * FAZ-IDX-01: Ingestion Rate vs SQL Indexing Health
 * Commands: diagnose fortilogd msgrate, diagnose test application sqlplugind 2
 * FAIL: (ingest_rate > 50 AND insert_rate === 0) OR (ingest_rate > 0 AND ratio < 0.50) OR io_utils >= 95
 * WARN: (ingest_rate > 0 AND ratio >= 0.50 AND ratio < 0.85) OR io_utils >= 80
 * PASS: ratio >= 0.85 AND io_utils < 80
 */
function checkFazIndexingPipeline(text) {
  if (
    !hasCommand(text, "diagnose fortilogd msgrate") &&
    !hasCommand(text, "diagnose test application sqlplugind 2") &&
    !/Log insert speed:/i.test(text) &&
    !/msgrate/i.test(text)
  ) {
    return null;
  }

  const ingest60Match = /last 60 seconds:\s*([\d.]+)/i.exec(text);
  const ingest30Match = /last 30 seconds:\s*([\d.]+)/i.exec(text);
  const ingestGenericMatch = /(?:received|msgrate)[^\n]*?:\s*([\d.]+)/i.exec(text);
  const ingest_rate = ingest60Match
    ? parseFloat(ingest60Match[1])
    : (ingest30Match ? parseFloat(ingest30Match[1]) : (ingestGenericMatch ? parseFloat(ingestGenericMatch[1]) : 0));

  const insertMatch = /logs\/60sec:\s*([\d.]+)/i.exec(text) || /insert speed[^\n]*?:\s*([\d.]+)/i.exec(text);
  let insert_rate = 0;
  if (insertMatch) {
    const rawVal = parseFloat(insertMatch[1]);
    if (/logs\/60sec:/i.test(insertMatch[0])) {
      insert_rate = Math.round((rawVal / 60) * 10) / 10;
    } else {
      insert_rate = rawVal;
    }
  }

  const ioMatch = /io-utils:\s*(\d+)%/i.exec(text) || /io_utils[^\n]*?:\s*(\d+)%/i.exec(text);
  const io_utils = ioMatch ? parseInt(ioMatch[1], 10) : 0;

  const ratioVal = ingest_rate > 0 ? (insert_rate / ingest_rate) : (insert_rate > 0 ? 1.0 : 1.0);
  const ratio = Math.round(ratioVal * 100);

  const data = {
    ingest_rate,
    insert_rate,
    ratio,
    io_utils
  };

  const observedBullets = [
    `  • Ingestion Rate: ${ingest_rate} logs/s (incoming from firewalls)`,
    `  • Insert Speed: ${insert_rate} logs/s (indexed to SQL database)`,
    `  • Indexing Ratio: ${ratio}% (Threshold: >= 85%)`,
    `  • Database Disk I/O: ${io_utils}% (Threshold: < 80%)`
  ].join("\n");

  const rootCause = "Firewalls are transmitting logs faster than the SQL engine can index them into the database (ratio < 50% or disk I/O saturated). Log searches and automated reports will lag.";
  const healthyBaseline = "Indexing Ratio >= 85% and Disk I/O < 80%.";
  const triageAction = "Inspect active report compilation and SQL plugin status: diagnose test application sqlplugind 2. If backlog is persistent, rebuild the SQL index: diagnose sql status rebuild-db.";

  const isStalled = ingest_rate > 50 && insert_rate === 0;
  const isSevereLag = ingest_rate > 100 && ratioVal < 0.50;
  const isDiskCritical = io_utils >= 95;

  if (isStalled || isSevereLag || isDiskCritical) {
    let reason = "";
    if (isStalled) {
      reason = "SQL indexing pipeline is stalled (0 logs/s indexed to database).";
    } else if (isDiskCritical) {
      reason = `Critical disk I/O saturation on database storage (${io_utils}% >= 95%).`;
    } else {
      reason = `Severe indexing backlog (ratio ${ratio}% < 50%).`;
    }

    return makeFinding({
      id: "FAZ-IDX-01",
      component: "SQL Log Indexing Pipeline",
      status: "FAIL",
      findingText: `FortiAnalyzer SQL indexing pipeline failure: ${reason}\n${observedBullets}\n\nRoot Cause & Meaning: ${rootCause}\nHealthy Baseline: ${healthyBaseline}`,
      actionText: triageAction,
      source: "cli",
      data
    });
  }

  const isModerateLag = ingest_rate > 0 && ratioVal >= 0.50 && ratioVal < 0.85;
  const isDiskWarn = io_utils >= 80;

  if (isModerateLag || isDiskWarn) {
    let reason = "";
    if (isDiskWarn) {
      reason = `Elevated disk I/O utilization on database storage (${io_utils}%).`;
    } else {
      reason = `Moderate SQL indexing lag (ratio ${ratio}%).`;
    }

    return makeFinding({
      id: "FAZ-IDX-01",
      component: "SQL Log Indexing Pipeline",
      status: "WARN",
      findingText: `FortiAnalyzer log processing bottleneck: ${reason}\n${observedBullets}\n\nRoot Cause & Meaning: ${rootCause}\nHealthy Baseline: ${healthyBaseline}`,
      actionText: triageAction,
      source: "cli",
      data
    });
  }

  return makeFinding({
    id: "FAZ-IDX-01",
    component: "SQL Log Indexing Pipeline",
    status: "PASS",
    findingText: `FortiAnalyzer log indexing pipeline is operating efficiently with real-time database insertion:\n${observedBullets}\n\nHealthy Baseline: ${healthyBaseline}`,
    actionText: "",
    source: "cli",
    data
  });
}

// =====================================================================
// =====================================================================
// DEEP RESEARCH PARSERS: AST LEXICAL PARSER & ENTITY GRAPH RESOLVER
// =====================================================================

class FortiOSSyntaxParser {
  constructor() {
    this.ast = { global: {}, vdoms: {} };
    this.scopeStack = [];
    this.currentVdom = null;
  }

  tokenize(configText) {
    const lines = configText.split(/\r?\n/);
    for (let rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;

      const tokens = line.split(/\s+/);
      const directive = tokens[0].toLowerCase();

      if (directive === 'config') {
        const section = tokens[1] ? tokens[1].toLowerCase() : '';
        const fullSection = tokens.slice(1).join(' ').toLowerCase();
        if (this.scopeStack.length === 0 && section === 'global') {
          this.currentVdom = 'global';
        }
        this.scopeStack.push({ type: 'config', name: section, fullName: fullSection });
      } else if (directive === 'edit') {
        const identifier = tokens[1] ? tokens[1].replace(/["']/g, '') : '';
        if (this.scopeStack.length === 1 && this.scopeStack[0].name === 'vdom') {
          this.currentVdom = identifier;
          if (!this.ast.vdoms[identifier]) this.ast.vdoms[identifier] = {};
        }
        this.scopeStack.push({ type: 'edit', id: identifier });
      } else if (directive === 'next') {
        this.scopeStack.pop();
      } else if (directive === 'end') {
        const popped = this.scopeStack.pop();
        if (this.scopeStack.length === 0 || (popped && popped.type === 'config' && popped.name === 'global')) {
          this.currentVdom = null;
        }
      } else if (directive === 'set') {
        this.assignAttribute(tokens[1], tokens.slice(2).join(' '));
      }
    }
    return this.ast;
  }

  assignAttribute(key, value) {
    let node = this.currentVdom && this.currentVdom !== 'global'
      ? this.ast.vdoms[this.currentVdom]
      : this.ast.global;

    if (!node) return;

    for (const frame of this.scopeStack) {
      if (frame.type === 'config') {
        if (frame.name === 'vdom') continue;
        const parts = (frame.fullName || frame.name).split(/\s+/);
        for (const p of parts) {
          if (!node[p]) node[p] = {};
          node = node[p];
        }
      } else if (frame.type === 'edit') {
        if (!node[frame.id]) node[frame.id] = {};
        node = node[frame.id];
      }
    }

    node[key] = value.replace(/^["']|["']$/g, '');
  }
}

class EntityGraphResolver {
  constructor(ast) {
    this.ast = ast;
    this.addressGroups = {};
    this.zones = {};
    this.init();
  }

  init() {
    const scopes = [this.ast.global, ...Object.values(this.ast.vdoms || {})].filter(Boolean);
    for (const scope of scopes) {
      const firewall = scope.firewall || {};
      const addrgrp = firewall['addrgrp'] || firewall['address-group'] || {};
      for (const [name, data] of Object.entries(addrgrp)) {
        if (data && data.member) {
          this.addressGroups[name] = data.member.split(/\s+/).map(m => m.replace(/["']/g, ''));
        }
      }

      const system = scope.system || {};
      const zones = system['zone'] || {};
      for (const [name, data] of Object.entries(zones)) {
        if (data && data.interface) {
          this.zones[name] = data.interface.split(/\s+/).map(i => i.replace(/["']/g, ''));
        }
      }
    }
  }

  resolveAddressGroup(groupName, visited = new Set()) {
    if (visited.has(groupName)) return [];
    visited.add(groupName);

    const members = this.addressGroups[groupName] || [];
    let resolved = [];

    for (const m of members) {
      if (this.addressGroups[m]) {
        resolved.push(...this.resolveAddressGroup(m, visited));
      } else {
        resolved.push(m);
      }
    }
    return resolved;
  }

  matchesZoneOrInterface(sourceTarget, interfaceName) {
    if (sourceTarget === interfaceName) return true;
    const members = this.zones[sourceTarget];
    if (members && members.includes(interfaceName)) return true;
    return false;
  }
}

// ---------------------------------------------------------------------
// 15 DEEP RESEARCH CHECKS (METAPLAN AUDIT SPECIFICATION)
// ---------------------------------------------------------------------

function checkCisBanners(text, ast) {
  if (!/(?:^|\n)\s*config\s+/i.test(text) && !/banner/i.test(text)) return null;

  const global = (ast && ast.global && ((ast.global.system && ast.global.system.global) || ast.global['system global'])) || {};
  const preBanner = (global['pre-login-banner'] || '').toLowerCase();
  const postBanner = (global['post-login-banner'] || '').toLowerCase();

  const prePass = preBanner === 'enable' || (!global['pre-login-banner'] && /set\s+pre-login-banner\s+enable/i.test(text));
  const postPass = postBanner === 'enable' || (!global['post-login-banner'] && /set\s+post-login-banner\s+enable/i.test(text));

  const isCompliant = prePass && postPass;
  return makeFinding({
    id: "CIS-MED-01",
    component: "System Global Banners",
    status: isCompliant ? "PASS" : "WARN",
    findingText: isCompliant
      ? "Pre-login and Post-login warning banners are enabled, enforcing legal access notices prior to shell and GUI access."
      : `Missing legal notification banners (Pre-login: ${prePass ? 'Enabled' : 'Disabled'}, Post-login: ${postPass ? 'Enabled' : 'Disabled'}).`,
    actionText: "Enable legal warning banners across all administrative entry points.",
    remediationCli: `config system global\n    set pre-login-banner enable\n    set post-login-banner enable\nend`,
    diagnosticCmd: DIAGNOSTIC_COMMANDS["CIS-MED-01"],
    targetConfig: "config system global"
  });
}

function checkCisAutoInstall(text, ast) {
  if (!/(?:^|\n)\s*config\s+/i.test(text) && !/auto-install/i.test(text)) return null;

  const autoInstall = (ast && ast.global && ((ast.global.system && ast.global.system['auto-install']) || ast.global['system auto-install'])) || {};
  const autoImage = (autoInstall['auto-install-image'] || '').toLowerCase();
  const autoConfig = (autoInstall['auto-install-config'] || '').toLowerCase();

  const isHardened = (autoImage === 'disable' || !/set\s+auto-install-image\s+enable/i.test(text)) &&
                     (autoConfig === 'disable' || !/set\s+auto-install-config\s+enable/i.test(text));

  return makeFinding({
    id: "CIS-HIGH-01",
    component: "USB Firmware/Config Auto-Install",
    status: isHardened ? "PASS" : "FAIL",
    findingText: isHardened
      ? "USB Auto-Installation of firmware images and configuration files is disabled."
      : "Insecure USB auto-install parameters detected. Unauthorized physical USB insertion could compromise system integrity.",
    actionText: "Disable USB automatic firmware and configuration installation.",
    remediationCli: `config system auto-install\n    set auto-install-image disable\n    set auto-install-config disable\nend`,
    diagnosticCmd: DIAGNOSTIC_COMMANDS["CIS-HIGH-01"],
    targetConfig: "config system auto-install"
  });
}

function checkSecUrpfAntiSpoofing(text, ast) {
  if (!/(?:^|\n)\s*config\s+/i.test(text) && !/src-check/i.test(text)) return null;

  let isLoose = false;
  let isStrict = false;
  let disabledIntfs = [];

  const scopes = [ast && ast.global, ...(ast && ast.vdoms ? Object.values(ast.vdoms) : [])].filter(Boolean);
  for (const s of scopes) {
    const settings = (s.system && s.system.settings) || s['system settings'] || {};
    const srcCheck = (settings['src-check'] || '').toLowerCase();
    const asymCheck = (settings['asym-route'] || '').toLowerCase();
    const strictCheck = (settings['strict-src-check'] || '').toLowerCase();
    if (strictCheck === 'enable' || (srcCheck === 'enable' && asymCheck === 'disable')) isStrict = true;
    else if (strictCheck === 'disable' || srcCheck === 'enable') isLoose = true;

    const intfs = (s.system && s.system.interface) || s['system interface'] || {};
    for (const [intfName, data] of Object.entries(intfs)) {
      if ((data['src-check'] || '').toLowerCase() === 'disable') {
        disabledIntfs.push(intfName);
      }
    }
  }

  if (!isStrict && /set\s+strict-src-check\s+enable/i.test(text)) {
    isStrict = true;
  } else if (!isLoose && /set\s+src-check\s+enable/i.test(text)) {
    isLoose = true;
  }
  if (disabledIntfs.length === 0) {
    const matches = text.matchAll(/edit\s+["']?([a-zA-Z0-9_-]+)["']?[\s\S]*?set\s+src-check\s+disable/gi);
    for (const m of matches) {
      disabledIntfs.push(m[1]);
    }
  }

  let status = "FAIL";
  let desc = "uRPF anti-spoofing is disabled across routing settings. Spoofed IP packets can bypass security policies.";
  if (disabledIntfs.length > 0) {
    status = "FAIL";
    desc = `uRPF source verification explicitly disabled on interface(s): ${disabledIntfs.join(', ')}. Inbound spoofed packets permitted.`;
  } else if (isStrict) {
    status = "PASS";
    desc = "Strict Unicast Reverse Path Forwarding (uRPF) anti-spoofing is actively enforced across FIB routing tables.";
  } else if (isLoose) {
    status = "WARN";
    desc = "Feasible Path (loose) uRPF anti-spoofing active (src-check enabled, asymmetric routing allowed).";
  }

  return makeFinding({
    id: "SEC-HIGH-02",
    component: "Anti-Spoofing & uRPF Enforcement",
    status,
    findingText: desc,
    actionText: "Enforce strict reverse path filtering on perimeter interfaces to block forged source addresses.",
    remediationCli: `config system settings\n    set strict-src-check enable\n    set asym-route disable\nend\nconfig system interface\n    edit <wan-interface>\n        set src-check enable\n    next\nend`,
    diagnosticCmd: DIAGNOSTIC_COMMANDS["SEC-HIGH-02"],
    targetConfig: "config system settings"
  });
}

function checkCisDnsOverTls(text, ast) {
  if (!/(?:^|\n)\s*config\s+/i.test(text) && !/system\s+dns/i.test(text)) return null;

  const dns = (ast && ast.global && ((ast.global.system && ast.global.system.dns) || ast.global['system dns'])) || {};
  const dot = (dns['dns-over-tls'] || dns['protocol'] || '').toLowerCase();
  const hostname = (dns['server-hostname'] || '').trim();
  const isDoT = dot === 'enable' || dot === 'enforce' || dot === 'dot' || dot === 'doh' || /set\s+(?:dns-over-tls\s+(?:enable|enforce)|protocol\s+(?:dot|doh))/i.test(text);
  const hasHostname = Boolean(hostname) || /set\s+server-hostname\s+["']?[^"'\s]+/i.test(text);
  const isCompliant = isDoT && (dot === 'doh' || hasHostname);

  return makeFinding({
    id: "CIS-MED-02",
    component: "Encrypted DNS Resolution (DoT)",
    status: isCompliant ? "PASS" : "WARN",
    findingText: isCompliant
      ? "DNS queries to upstream resolvers are encrypted via DNS-over-TLS (DoT/DoH) with server-hostname SNI validation."
      : "System DNS queries transmit in cleartext (UDP/53) or lack SNI verification. Upstream resolution is vulnerable to eavesdropping and cache poisoning.",
    actionText: "Enable DNS-over-TLS (DoT) upstream to protect system resolutions from MITM tampering.",
    remediationCli: `config system dns\n    set protocol dot\n    set server-hostname "cloudflare-dns.com"\nend`,
    diagnosticCmd: DIAGNOSTIC_COMMANDS["CIS-MED-02"],
    targetConfig: "config system dns"
  });
}

function checkSecAdminMfa(text, ast) {
  if (!/(?:^|\n)\s*config\s+/i.test(text) && !/system\s+admin/i.test(text)) return null;

  let unhardenedAdmins = [];
  let totalAdmins = 0;
  const scopes = [ast && ast.global, ...(ast && ast.vdoms ? Object.values(ast.vdoms) : [])].filter(Boolean);
  for (const s of scopes) {
    const admins = (s.system && s.system.admin) || s['system admin'] || {};
    for (const [adminName, data] of Object.entries(admins)) {
      totalAdmins++;
      const twoFactor = (data['two-factor'] || data['two-factor-authentication'] || '').toLowerCase();
      const trusthost = (data['trusthost1'] || data['trusthost'] || '');
      if (!twoFactor || twoFactor === 'disable') {
        if (!trusthost) {
          unhardenedAdmins.push(adminName);
        }
      }
    }
  }

  if (totalAdmins === 0) {
    const adminBlocks = text.split(/(?:^|\n)\s*edit\s+/i);
    for (let i = 1; i < adminBlocks.length; i++) {
      const block = adminBlocks[i];
      if (/set\s+password|set\s+accprofile/i.test(block)) {
        totalAdmins++;
        const m = block.match(/^["']?([a-zA-Z0-9_-]+)["']?/);
        const name = m ? m[1] : `admin_${i}`;
        const has2fa = /set\s+(?:two-factor|two-factor-authentication)\s+(?:enable|fortitoken|email|sms)/i.test(block);
        const hasTrusthost = /set\s+trusthost\d*\s+\S+/i.test(block);
        if (!has2fa && !hasTrusthost) {
          unhardenedAdmins.push(name);
        }
      }
    }
  }

  if (totalAdmins === 0) return null;

  const isPass = unhardenedAdmins.length === 0;
  return makeFinding({
    id: "SEC-HIGH-01",
    component: "Administrative Multi-Factor Authentication",
    status: isPass ? "PASS" : "FAIL",
    findingText: isPass
      ? "All administrative accounts enforce multi-factor authentication (FortiToken/Email/SMS/RADIUS MFA) or explicit trusted host restrictions."
      : `Administrative account(s) missing mandatory MFA: ${unhardenedAdmins.slice(0, 5).join(', ')}${unhardenedAdmins.length > 5 ? ' (+' + (unhardenedAdmins.length - 5) + ')' : ''}.`,
    actionText: "Mandate hardware or software two-factor authentication on all administrative profiles.",
    remediationCli: `config system admin\n    edit <admin_user>\n        set two-factor fortitoken\n        set fortitoken <token_sn>\n    next\nend`,
    diagnosticCmd: DIAGNOSTIC_COMMANDS["SEC-HIGH-01"],
    targetConfig: "config system admin"
  });
}

function checkSecSslSshProfile(text, ast) {
  if (!/(?:^|\n)\s*config\s+/i.test(text) && !/ssl-ssh-profile/i.test(text)) return null;

  let weakProfiles = [];
  let totalProfiles = 0;
  const scopes = [ast && ast.global, ...(ast && ast.vdoms ? Object.values(ast.vdoms) : [])].filter(Boolean);
  for (const s of scopes) {
    const profiles = (s.firewall && (s.firewall['ssl-ssh-profile'] || s.firewall.ssl_ssh_profile)) || s['firewall ssl-ssh-profile'] || {};
    for (const [profName, data] of Object.entries(profiles)) {
      totalProfiles++;
      const minVer = (data['ssl-min-proto-ver'] || data['min-allowed-ssl-version'] || (data.https && data.https['min-allowed-ssl-version']) || '').toLowerCase();
      const allowSsl3 = (data['allow-ssl-3.0'] || (data.https && data.https['allow-ssl-3.0']) || '').toLowerCase();
      const untrusted = (data['untrusted-server-cert'] || (data.https && data.https['untrusted-server-cert']) || '').toLowerCase();
      if (allowSsl3 === 'enable' || minVer === 'tls-1.0' || minVer === 'tls-1.1' || minVer === 'ssl-3.0' || untrusted === 'allow') {
        weakProfiles.push(profName);
      }
    }
  }

  if (totalProfiles === 0) {
    const profBlocks = text.split(/(?:^|\n)\s*edit\s+/i);
    for (let i = 1; i < profBlocks.length; i++) {
      const b = profBlocks[i];
      if (/min-allowed-ssl-version|ssl-min-proto-ver|untrusted-server-cert/i.test(b)) {
        totalProfiles++;
        const m = b.match(/^["']?([a-zA-Z0-9_-]+)["']?/);
        const name = m ? m[1] : `profile_${i}`;
        if (/min-allowed-ssl-version\s+(?:tls-1\.[01]|ssl-3\.0)/i.test(b) || /untrusted-server-cert\s+allow/i.test(b) || /allow-ssl-3\.0\s+enable/i.test(b)) {
          weakProfiles.push(name);
        }
      }
    }
  }

  if (totalProfiles === 0) return null;

  const isHardened = weakProfiles.length === 0;
  return makeFinding({
    id: "SEC-MED-01",
    component: "Deep Inspection Cipher Hardening",
    status: isHardened ? "PASS" : "WARN",
    findingText: isHardened
      ? "SSL/SSH inspection profiles enforce secure cipher suites and mandate TLS 1.2+ minimum protocols."
      : `SSL/SSH inspection profile(s) permit legacy protocols (SSLv3/TLS 1.0/TLS 1.1) or allow untrusted certs: ${weakProfiles.join(', ')}.`,
    actionText: "Harden SSL inspection profiles to reject obsolete ciphers and require TLS 1.2 or TLS 1.3.",
    remediationCli: `config firewall ssl-ssh-profile\n    edit <profile-name>\n        set min-allowed-ssl-version tls-1.2\n        set untrusted-server-cert block\n    next\nend`,
    diagnosticCmd: DIAGNOSTIC_COMMANDS["SEC-MED-01"],
    targetConfig: "config firewall ssl-ssh-profile"
  });
}

function checkSecFgfmExposure(text, ast) {
  if (!/(?:^|\n)\s*config\s+/i.test(text) && !/fgfm/i.test(text)) return null;

  let exposedIntfs = [];
  const scopes = [ast && ast.global, ...(ast && ast.vdoms ? Object.values(ast.vdoms) : [])].filter(Boolean);
  for (const s of scopes) {
    const intfs = (s.system && s.system.interface) || s['system interface'] || {};
    for (const [intfName, data] of Object.entries(intfs)) {
      const allow = Array.isArray(data['allowaccess']) ? data['allowaccess'].join(' ').toLowerCase() : (data['allowaccess'] || '').toLowerCase();
      const role = (data['role'] || '').toLowerCase();
      if (allow.includes('fgfm') && (role === 'wan' || /wan|port1|internet/i.test(intfName))) {
        exposedIntfs.push(intfName);
      }
    }
  }

  if (exposedIntfs.length === 0 && /allowaccess[^\n]*fgfm/i.test(text)) {
    const intfBlocks = text.split(/(?:^|\n)\s*edit\s+/i);
    for (const block of intfBlocks) {
      if (/set\s+allowaccess\b[^\n]*\bfgfm\b/i.test(block) && (/set\s+role\s+wan\b/i.test(block) || /["']?(wan\d*|port1)["']/i.test(block.slice(0, 30)))) {
        const m = block.match(/^["']?([a-zA-Z0-9_-]+)["']?/);
        exposedIntfs.push(m ? m[1] : "wan");
      }
    }
  }

  const isSecure = exposedIntfs.length === 0;
  return makeFinding({
    id: "SEC-CRIT-01",
    component: "FortiGate to FortiManager (FGFM) Exposure",
    status: isSecure ? "PASS" : "FAIL",
    findingText: isSecure
      ? "FortiManager protocol (FGFM/TCP 541) is not exposed on perimeter external interfaces."
      : `Critical Perimeter Vulnerability: FGFM management protocol (TCP 541) exposed on external interface(s): ${exposedIntfs.join(', ')} (CVE-2024-23113 risk).`,
    actionText: "Strip fgfm protocol from allowaccess on all public-facing WAN interfaces immediately.",
    remediationCli: `config system interface\n    edit <wan-interface>\n        set allowaccess ping https ssh\n    next\nend`,
    diagnosticCmd: DIAGNOSTIC_COMMANDS["SEC-CRIT-01"],
    targetConfig: "config system interface"
  });
}

function checkSecSslVpnWebMode(text, ast) {
  let foundAnyPortal = false;
  const vulnerablePortals = [];

  // 1. Try AST evaluation first (strictly within config vpn ssl web portal)
  if (ast) {
    const scopes = [ast.global, ...(ast.vdoms ? Object.values(ast.vdoms) : [])].filter(Boolean);
    for (const s of scopes) {
      const portals = (s.vpn && s.vpn.ssl && s.vpn.ssl.web && s.vpn.ssl.web.portal) ||
                      (s.vpn && (s.vpn['ssl web portal'] || (s.vpn.ssl && s.vpn.ssl.web && s.vpn.ssl.web.portal))) ||
                      s['vpn ssl web portal'] || null;
      if (portals && typeof portals === 'object') {
        for (const [portalName, data] of Object.entries(portals)) {
          if (!data || typeof data !== 'object') continue;
          foundAnyPortal = true;
          const webMode = (data['web-mode'] || '').toLowerCase();
          if (webMode === 'enable') {
            vulnerablePortals.push(portalName);
          }
        }
      }
    }
  }

  // 2. Fallback or Raw Text Scoped Evaluation: Strictly within 'config vpn ssl web portal ... end'
  if (!foundAnyPortal && text) {
    const portalSectionRe = /config\s+vpn\s+ssl\s+web\s+portal\b([\s\S]*?)(?:\n\s*end\b|$)/gi;
    let secMatch;
    while ((secMatch = portalSectionRe.exec(text)) !== null) {
      const secBody = secMatch[1];
      const editBlocks = secBody.split(/(?:^|\n)\s*edit\s+/i);
      for (let i = 1; i < editBlocks.length; i++) {
        const block = editBlocks[i];
        const nameMatch = block.match(/^["']?([a-zA-Z0-9_.-]+)["']?/);
        const portalName = nameMatch ? nameMatch[1] : `portal_${i}`;
        foundAnyPortal = true;
        // Strictly check if web-mode enable is explicitly set in this edit block
        if (/set\s+web-mode\s+enable\b/i.test(block)) {
          vulnerablePortals.push(portalName);
        }
      }
    }
  }

  if (!foundAnyPortal) return null;

  const uniqueVulnerable = [...new Set(vulnerablePortals)];
  const isHardened = uniqueVulnerable.length === 0;

  return makeFinding({
    id: "SEC-CRIT-02",
    component: "SSL-VPN Web Mode Perimeter Exposure",
    status: isHardened ? "PASS" : "FAIL",
    findingText: isHardened
      ? "SSL-VPN Web Mode is completely disabled. Gateway operates in Tunnel Mode only."
      : `Critical Exposure: SSL-VPN Web Mode (HTML5 bookmarks / reverse proxy) enabled on portal(s): ${uniqueVulnerable.join(', ')}. Disabling web mode eliminates primary remote exploit vectors (CVE-2023-27997, CVE-2024-21762).`,
    actionText: "Disable web-mode on all SSL-VPN portals and enforce strictly tunnel-mode access.",
    remediationCli: `config vpn ssl web portal\n    edit <portal-name>\n        set web-mode disable\n    next\nend`,
    diagnosticCmd: DIAGNOSTIC_COMMANDS["SEC-CRIT-02"],
    targetConfig: "config vpn ssl web portal"
  });
}

function checkSecFortiOSLifecycle(text) {
  const m = /FortiOS\s+[vV]?(\d+)\.(\d+)\.(\d+)(?:[\s,]+build(\d+))?/i.exec(text) ||
            /Version:\s*FortiGate[\w-]*\s+v?(\d+)\.(\d+)\.(\d+),build(\d+)/i.exec(text) ||
            /#config-version=[A-Za-z0-9_-]*-(\d+)\.(\d+)\.(\d+)(?:-FW)?-build(\d+)/i.exec(text);

  if (!m) return null;
  const major = parseInt(m[1], 10);
  const minor = parseInt(m[2], 10);
  const patch = parseInt(m[3], 10);
  const build = m[4] ? parseInt(m[4], 10) : null;
  const verStr = `${major}.${minor}.${patch}` + (build ? ` build${build}` : "");

  let status = "PASS";
  let finding = `Firmware branch ${verStr} is within active support maintenance.`;

  if (major < 7 || (major === 7 && minor === 0 && patch < 14)) {
    status = "FAIL";
    finding = `End-of-Life (EOL) FortiOS branch detected: ${verStr}. Upstream vendor security engineering has terminated active security patches for this branch.`;
  } else if (major === 7 && minor === 0 && build && build < 564) {
    status = "FAIL";
    finding = `Vulnerable FortiOS 7.0 build detected (${verStr} < build 0564). Susceptible to critical pre-auth RCE vulnerabilities (CVE-2024-21762).`;
  } else if (major === 7 && minor === 2 && build && build < 1637) {
    status = "FAIL";
    finding = `Vulnerable FortiOS 7.2 build detected (${verStr} < build 1637). Critical authentication bypass vulnerabilities active (CVE-2024-23113).`;
  } else if (major === 7 && minor === 0) {
    status = "WARN";
    finding = `FortiOS 7.0 (${verStr}) is past End of Engineering Support (EOES). Upstream maintenance limited to critical PSIRT patches until Sept 2025.`;
  } else if (major === 7 && minor === 2 && (patch < 8 || (build && build < 1637))) {
    status = "FAIL";
    finding = `Vulnerable FortiOS 7.2 release detected (${verStr} < 7.2.8). Critical FGFM format string RCE (CVE-2024-23113) unpatched.`;
  }

  return makeFinding({
    id: "SEC-LIFE-01",
    altId: "SEC-CRIT-03",
    component: "Firmware Lifecycle & Patch Governance",
    status,
    findingText: finding,
    actionText: "Upgrade appliance firmware to current Fortinet recommended patch branch.",
    remediationCli: "# Execute coordinated firmware image verification and install:\nexecute restore image tftp <image-file> <tftp-server>",
    diagnosticCmd: DIAGNOSTIC_COMMANDS["SEC-LIFE-01"],
    targetConfig: "get system status"
  });
}

function checkOpsWadWorkers(text) {
  if (!text.includes("application wad") && !text.includes("diagnose test application wad") && !text.includes("WAD manager")) return null;

  const lines = text.split(/\r?\n/);
  const workers = [];
  let deadlocks = 0;

  for (const line of lines) {
    const m = /type=worker.*?pid=(\d+).*?req=(\d+).*?mem=(\d+)MB/i.exec(line) ||
              /worker.*?pid[=:\s]+(\d+).*?mem[=:\s]+(\d+)MB/i.exec(line) ||
              /worker\s+(\d+).*?mem=(\d+)MB/i.exec(line);

    if (m) {
      if (m.length === 4) {
        workers.push({ pid: m[1], req: parseInt(m[2], 10), mem: parseInt(m[3], 10) });
      } else {
        workers.push({ pid: m[1], req: null, mem: parseInt(m[2], 10) });
      }
    }
    if (/deadlock|stuck|zombie|unresponsive/i.test(line)) {
      deadlocks++;
    }
  }

  if (workers.length === 0 && deadlocks === 0) return null;

  let memLeakWorkers = [];
  let frozenWorkers = [];
  let totalMem = 0;

  if (workers.length > 0) {
    const avgMem = workers.reduce((acc, w) => acc + w.mem, 0) / workers.length;
    const maxReq = Math.max(...workers.map(w => w.req || 0));

    for (const w of workers) {
      totalMem += w.mem;
      if (w.mem > 500 || (workers.length > 1 && avgMem > 50 && w.mem > avgMem * 1.5)) {
        memLeakWorkers.push(`PID ${w.pid} (${w.mem}MB)`);
      }
      if (w.req !== null && w.req === 0 && maxReq > 1000) {
        frozenWorkers.push(`PID ${w.pid} (req=0 vs peer req=${maxReq})`);
      }
    }
  }

  let status = "PASS";
  let details = `WAD proxy cluster healthy: ${workers.length} worker(s) active, total memory ${totalMem}MB. Zero deadlocks.`;

  if (deadlocks > 0 || frozenWorkers.length > 0 || memLeakWorkers.length > 0) {
    status = "FAIL";
    const reasons = [];
    if (deadlocks > 0) reasons.push(`${deadlocks} deadlock(s)`);
    if (frozenWorkers.length > 0) reasons.push(`Worker deadlock/freeze: ${frozenWorkers.join(', ')}`);
    if (memLeakWorkers.length > 0) reasons.push(`Memory leak/asymmetry (>500MB or divergence): ${memLeakWorkers.join(', ')}`);
    details = `WAD Proxy Issues Detected: ${reasons.join('; ')}. Cumulative footprint: ${totalMem}MB.`;
  } else if (totalMem > 1000) {
    status = "WARN";
    details = `WAD proxy elevated cluster footprint: ${totalMem}MB across ${workers.length} workers.`;
  }

  return makeFinding({
    id: "OPS-MEM-01",
    altId: "OPS-HIGH-01",
    component: "WAD Worker Process Health & Memory Consumption",
    status,
    findingText: details,
    actionText: "Restart deadlocked WAD proxy worker pool or upgrade to resolve memory leak defect.",
    remediationCli: "diagnose test application wad 99",
    diagnosticCmd: DIAGNOSTIC_COMMANDS["OPS-MEM-01"],
    targetConfig: "diagnose test application wad 1000"
  });
}

function checkOpsHaHistory(text) {
  if (!text.includes("ha history") && !text.includes("diagnose sys ha history") && !/\[(Master Change|Heartbeat Lost|Split-Brain|Link Failure)\]/i.test(text)) return null;

  let masterChanges = 0;
  let splitBrain = false;
  let heartbeatLost = false;
  let linkFailures = 0;
  const lines = text.split(/\r?\n/);

  for (const line of lines) {
    if (/Split-Brain/i.test(line)) splitBrain = true;
    if (/Heartbeat Lost/i.test(line)) heartbeatLost = true;
    if (/\[Master Change\]|became\s+master|becomes\s+master/i.test(line)) masterChanges++;
    if (/\[Link Failure\]|mondev\s+down/i.test(line)) linkFailures++;
  }

  let status = "PASS";
  let details = "HA cluster election state stable. Zero unexpected failover, heartbeat disruptions, or split-brain states recorded.";

  if (splitBrain || heartbeatLost) {
    status = "FAIL";
    details = `Critical HA Integrity Alert: ${splitBrain ? 'Split-Brain detected (both units operated as Master simultaneously)' : 'Heartbeat connection lost'}. Risk of MAC flapping and dual-primary traffic disruption.`;
  } else if (masterChanges > 3) {
    status = "FAIL";
    details = `Severe HA Cluster Flapping: ${masterChanges} Master failover transitions logged. Monitored interface link failures: ${linkFailures}.`;
  } else if (masterChanges > 0 || linkFailures > 0) {
    status = "WARN";
    details = `HA cluster experienced ${masterChanges} failover transition(s) and ${linkFailures} link failure event(s) in history log.`;
  }

  return makeFinding({
    id: "OPS-HA-01",
    altId: "OPS-HIGH-02",
    component: "HA Failover History & Flapping Analysis",
    status,
    findingText: details,
    actionText: "Investigate HA heartbeat link stability and peer checksum discrepancies.",
    remediationCli: "diagnose sys ha checksum recalculate\ndiagnose sys ha checksum show",
    diagnosticCmd: DIAGNOSTIC_COMMANDS["OPS-HA-01"],
    targetConfig: "diagnose sys ha history read"
  });
}

function checkOpsRatingServers(text) {
  if (!text.includes("diagnose debug rating") && !/Server:\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*?Latency/i.test(text) && !/RTT\s*=/i.test(text)) return null;

  const lines = text.split(/\r?\n/);
  const servers = [];

  for (const line of lines) {
    const m1 = /Server:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?Latency:\s*(\d+)\s*ms.*?Lost:\s*(\d+)%.*?Active:\s*(Yes|No)/i.exec(line);
    if (m1) {
      servers.push({
        ip: m1[1],
        latency: parseInt(m1[2], 10),
        lost: parseInt(m1[3], 10),
        active: m1[4].toLowerCase() === 'yes'
      });
      continue;
    }
    const m2 = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?RTT\s*=\\s*(\d+)/i.exec(line);
    if (m2) {
      servers.push({
        ip: m2[1],
        latency: parseInt(m2[2], 10),
        lost: 0,
        active: true
      });
    }
  }

  if (servers.length === 0) return null;

  const activeServer = servers.find(s => s.active) || servers[0];
  const minLatencyServer = servers.reduce((prev, curr) => curr.latency < prev.latency ? curr : prev, servers[0]);

  let status = "PASS";
  let details = `FortiGuard Anycast rating latency healthy: Active server ${activeServer.ip} latency ${activeServer.latency}ms, packet loss ${activeServer.lost}%.`;

  if (activeServer.latency > 150 || activeServer.lost > 5) {
    status = activeServer.latency > 300 || activeServer.lost > 10 ? "FAIL" : "WARN";
    details = `FortiGuard Cloud Rating Degradation: Active server ${activeServer.ip} latency is ${activeServer.latency}ms (threshold 150ms), packet loss ${activeServer.lost}%.`;
    if (minLatencyServer && minLatencyServer.ip !== activeServer.ip && minLatencyServer.latency < activeServer.latency - 50) {
      details += ` Suboptimal routing: Alternate server ${minLatencyServer.ip} offers much lower latency (${minLatencyServer.latency}ms).`;
    }
  }

  return makeFinding({
    id: "OPS-DNS-01",
    altId: "OPS-MED-01",
    component: "FortiGuard Anycast Rating Latency & Health",
    status,
    findingText: details,
    actionText: "Flush FortiGuard Anycast cache or transition to HTTPS over port 443.",
    remediationCli: `diagnose webfilter fortiguard cache flush\nconfig system fortiguard\n    set fortiguard-anycast disable\n    set protocol https\n    set port 443\nend`,
    diagnosticCmd: DIAGNOSTIC_COMMANDS["OPS-DNS-01"],
    targetConfig: "diagnose debug rating"
  });
}

function checkOpsBgpDampening(text) {
  if (!text.includes("BGP dampening") && !text.includes("flap-statistics") && !text.includes("dampened-paths")) return null;

  const lines = text.split(/\r?\n/);
  let dampenedRoutes = 0;
  let flappingPrefixes = 0;

  for (const line of lines) {
    if (/^\s*[*]?\s*d\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}/i.test(line) || /\bState:\s*dampened\b/i.test(line)) {
      dampenedRoutes++;
    }
    const flapMatch = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}\b.*?(\d+)\s+flaps/i.exec(line) ||
                      /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}\b\s+\d+\s+(\d+)/i.exec(line);
    if (flapMatch) {
      const count = parseInt(flapMatch[1], 10);
      if (count > 0) flappingPrefixes++;
      if (count > 10) dampenedRoutes++;
    }
  }

  let status = "PASS";
  let details = "Dynamic BGP routing tables are stable. Zero route flapping or penalty damping events recorded.";

  if (dampenedRoutes > 0) {
    status = "FAIL";
    details = `Critical BGP Route Suppression: ${dampenedRoutes} route(s) actively dampened or flapping excessively. Packet forwarding may fail for suppressed paths.`;
  } else if (flappingPrefixes > 0) {
    status = "WARN";
    details = `BGP Route Churn: ${flappingPrefixes} prefix(es) fluctuating in routing table.`;
  }

  return makeFinding({
    id: "OPS-BGP-01",
    altId: "OPS-MED-02",
    component: "BGP Route Churn & Flap Damping",
    status,
    findingText: details,
    actionText: "Inspect upstream peer BGP advertisement stability and tune route-flap dampening half-life.",
    remediationCli: `config router bgp\n    set dampening enable\n    set dampening-half-life 15\nend`,
    diagnosticCmd: DIAGNOSTIC_COMMANDS["OPS-BGP-01"],
    targetConfig: "get router info bgp dampening flap-statistics"
  });
}

function checkFazSilentForwarder(text) {
  if (!text.includes("lograte-device") && !text.includes("oftpd") && !/Rate\(1hr\)/i.test(text)) return null;

  const lines = text.split(/\r?\n/);
  let silentDevices = [];

  for (const line of lines) {
    const m = /([a-zA-Z0-9_-]+)\s+.*?Rate\(1hr\)\s*=\s*0(\.0+)?/i.exec(line) ||
              /([a-zA-Z0-9_-]+)\s+.*?current\s*=\s*0(\.0+)?/i.exec(line);
    if (m && !m[1].toLowerCase().includes("total") && !m[1].toLowerCase().includes("device")) {
      silentDevices.push(m[1]);
    }
  }

  if (silentDevices.length === 0) return null;

  return makeFinding({
    id: "FAZ-FWD-01",
    altId: "FAZ-HIGH-01",
    component: "FortiAnalyzer Connected Forwarder Inactivity",
    status: "WARN",
    findingText: `Silent logging forwarder detected: device(s) connected via OFTPD but emitting 0 logs/hr (Rate(1hr) == 0.0): ${silentDevices.join(', ')}.`,
    actionText: "Verify firewall miglogd daemon transmission and inspect network logging filters.",
    remediationCli: "diagnose test application miglogd 6",
    diagnosticCmd: DIAGNOSTIC_COMMANDS["FAZ-FWD-01"],
    targetConfig: "diagnose fortilogd lograte-device"
  });
}

function checkFazRaidHealth(text) {
  if (!text.includes("RAID") && !text.includes("raid status") && !text.includes("Disk Array")) return null;

  let isDegraded = false;
  let isRebuilding = false;
  let failedDrives = [];

  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    if (/\b(?:Degraded|Failed|Unavailable)\b/i.test(line)) {
      isDegraded = true;
    }
    if (/\b(?:Rebuilding|Synchronizing)\b/i.test(line)) {
      isRebuilding = true;
    }
    const driveMatch = /(?:Disk|Drive)\s*#?(\d+).*?\b(Failed|Unavailable|Spare)\b/i.exec(line);
    if (driveMatch) {
      failedDrives.push(`Drive ${driveMatch[1]} (${driveMatch[2]})`);
    }
  }

  let status = "PASS";
  let details = "FortiAnalyzer physical storage RAID array status is optimal (clean/in-sync).";

  if (isDegraded || failedDrives.length > 0) {
    status = "FAIL";
    details = `Critical Storage Array Failure: FortiAnalyzer RAID status is DEGRADED/FAILED. ${failedDrives.length > 0 ? failedDrives.join(', ') : 'Hardware disk drive failure detected'}.`;
  } else if (isRebuilding) {
    status = "WARN";
    details = "FortiAnalyzer RAID array is currently rebuilding. I/O performance will be throttled.";
  }

  return makeFinding({
    id: "FAZ-DISK-01",
    altId: "FAZ-CRIT-01",
    component: "FortiAnalyzer Physical Storage & RAID Integrity",
    status,
    findingText: details,
    actionText: "Replace defective physical hard disk drive and verify automatic array rebuild.",
    remediationCli: "diagnose system raid status",
    diagnosticCmd: DIAGNOSTIC_COMMANDS["FAZ-DISK-01"],
    targetConfig: "diagnose system raid status"
  });
}


// ENGINE 2: CONFIGURATION FILE (.CONF / .CFG) TOKENIZER & PARSER
// =====================================================================

class FortiOSConfigTokenizer {
  constructor(configText) {
    this.rawText = configText;
    this.sections = {};
    this.vdoms = { root: {} };
    this.currentVdom = "root";
    this.vdomContext = ["root"];
    this.tokenize();
  }

  tokenize() {
    const lines = this.rawText.split(/\r?\n/);
    const sectionStack = [];
    let inVdomConfig = false;
    let activeVdomEdit = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith("#")) continue;

      if (/^config\s+vdom$/i.test(line) && sectionStack.length === 0) {
        inVdomConfig = true;
        continue;
      }

      if (/^config\s+global$/i.test(line) && sectionStack.length === 0) {
        this.currentVdom = "global";
        if (!this.vdoms["global"]) this.vdoms["global"] = {};
        this.vdomContext.push("global");
        continue;
      }

      if (/^config\s+/i.test(line)) {
        const sectionName = line.replace(/^config\s+/i, "").trim().toLowerCase();
        sectionStack.push({
          name: sectionName,
          entries: {},
          properties: {},
          currentEdit: null,
          vdom: this.currentVdom,
        });
        continue;
      }

      if (/^end$/i.test(line)) {
        if (sectionStack.length > 0) {
          const finished = sectionStack.pop();
          const targetVdom = finished.vdom || this.currentVdom || "root";
          if (!this.vdoms[targetVdom]) {
            this.vdoms[targetVdom] = {};
          }
          if (!this.vdoms[targetVdom][finished.name]) {
            this.vdoms[targetVdom][finished.name] = finished;
          } else {
            Object.assign(this.vdoms[targetVdom][finished.name].entries, finished.entries);
            Object.assign(this.vdoms[targetVdom][finished.name].properties, finished.properties);
          }

          if (sectionStack.length > 0) {
            const parentSec = sectionStack[sectionStack.length - 1];
            parentSec.subSections = parentSec.subSections || {};
            parentSec.subSections[finished.name] = finished;
            const compKey = `${parentSec.name}::${finished.name}`;
            if (!this.vdoms[targetVdom][compKey]) {
              this.vdoms[targetVdom][compKey] = finished;
            } else {
              Object.assign(this.vdoms[targetVdom][compKey].entries, finished.entries);
              Object.assign(this.vdoms[targetVdom][compKey].properties, finished.properties);
            }
          }

          if (targetVdom === "root" || !this.sections[finished.name]) {
            if (!this.sections[finished.name]) {
              this.sections[finished.name] = finished;
            } else {
              Object.assign(this.sections[finished.name].entries, finished.entries);
              Object.assign(this.sections[finished.name].properties, finished.properties);
            }
          }
        } else if (inVdomConfig && !activeVdomEdit) {
          inVdomConfig = false;
          this.currentVdom = "root";
        } else if (this.currentVdom === "global") {
          this.currentVdom = "root";
          if (this.vdomContext.length > 1) this.vdomContext.pop();
        }
        continue;
      }

      if (inVdomConfig && sectionStack.length === 0) {
        const vdomEditMatch = /^edit\s+(?:"([^"]+)"|(\S+))/i.exec(line);
        if (vdomEditMatch) {
          activeVdomEdit = (vdomEditMatch[1] || vdomEditMatch[2]).toLowerCase();
          this.currentVdom = activeVdomEdit;
          if (!this.vdoms[this.currentVdom]) {
            this.vdoms[this.currentVdom] = {};
          }
          this.vdomContext.push(this.currentVdom);
          continue;
        }

        if (/^next$/i.test(line)) {
          activeVdomEdit = null;
          this.currentVdom = "root";
          if (this.vdomContext.length > 1) this.vdomContext.pop();
          continue;
        }
      }

      const currentSection = sectionStack[sectionStack.length - 1];
      if (!currentSection) continue;

      const editMatch = /^edit\s+(?:"([^"]+)"|(\S+))/i.exec(line);
      if (editMatch) {
        const editName = editMatch[1] || editMatch[2];
        currentSection.currentEdit = {
          name: editName,
          properties: {},
          vdom: currentSection.vdom || this.currentVdom || "root",
        };
        currentSection.entries[editName] = currentSection.currentEdit;
        continue;
      }

      if (/^next$/i.test(line)) {
        if (currentSection.currentEdit) {
          currentSection.currentEdit = null;
        }
        continue;
      }

      const setMatch = /^set\s+(\S+)(?:\s+(.+))?$/i.exec(line);
      if (setMatch) {
        const key = setMatch[1].toLowerCase();
        const value = (setMatch[2] || "").trim();

        if (currentSection.currentEdit) {
          currentSection.currentEdit.properties[key] = value;
        } else {
          currentSection.properties[key] = value;
        }
      }
    }
  }

  getSection(name, vdom = "root") {
    const lowerName = name.toLowerCase();
    if (vdom && this.vdoms[vdom] && this.vdoms[vdom][lowerName]) {
      return this.vdoms[vdom][lowerName];
    }
    const SYSTEM_GLOBAL_SECTIONS = new Set([
      "system global", "system ntp", "system dns", "system password-policy",
      "system snmp community", "system snmp user", "system snmp sysinfo",
      "log fortianalyzer setting", "log syslogd setting", "system admin",
      "user saml", "system saml"
    ]);
    if (SYSTEM_GLOBAL_SECTIONS.has(lowerName)) {
      if (this.vdoms["global"] && this.vdoms["global"][lowerName]) {
        return this.vdoms["global"][lowerName];
      }
      if (this.vdoms["root"] && this.vdoms["root"][lowerName]) {
        return this.vdoms["root"][lowerName];
      }
      if (this.sections[lowerName]) {
        return this.sections[lowerName];
      }
    }
    if (vdom && this.vdoms[vdom]) {
      return null;
    }
    return this.sections[lowerName] || null;
  }

  getProperty(sectionName, key, vdom = "root") {
    const sec = this.getSection(sectionName, vdom);
    if (!sec) return null;
    return sec.properties[key.toLowerCase()] || null;
  }

  getSystemProperty(sectionName, prop) {
    const s = sectionName.toLowerCase();
    const p = prop.toLowerCase();
    return this.getProperty(s, p, "global") ||
           this.getProperty(s, p, "root") ||
           (this.sections[s] && this.sections[s].properties ? this.sections[s].properties[p] : null) ||
           null;
  }

  getSystemGlobalProperty(prop) {
    return this.getSystemProperty("system global", prop);
  }

  getSystemSection(name) {
    const lowerName = name.toLowerCase();
    if (this.vdoms["global"] && this.vdoms["global"][lowerName]) {
      return this.vdoms["global"][lowerName];
    }
    if (this.vdoms["root"] && this.vdoms["root"][lowerName]) {
      return this.vdoms["root"][lowerName];
    }
    return this.sections[lowerName] || null;
  }

  getEntries(sectionName, vdom = null) {
    const lowerName = sectionName.toLowerCase();
    if (vdom !== null) {
      const sec = this.getSection(lowerName, vdom);
      return sec ? sec.entries : {};
    }

    const allEntries = {};
    for (const v of this.getAllVdoms()) {
      const vdomSec = this.vdoms[v] ? this.vdoms[v][lowerName] : null;
      if (vdomSec && vdomSec.entries) {
        for (const [key, val] of Object.entries(vdomSec.entries)) {
          allEntries[`${v}::${key}`] = { ...val, _vdom: v, _origKey: key };
        }
      }
    }
    if (Object.keys(allEntries).length === 0 && this.sections[lowerName]) {
      return this.sections[lowerName].entries || {};
    }
    return allEntries;
  }

  getAllVdoms() {
    const vdomSet = new Set(["root", ...Object.keys(this.vdoms)]);
    return Array.from(vdomSet);
  }

  getAllSections(vdom = "root") {
    if (this.vdoms[vdom]) {
      return Object.keys(this.vdoms[vdom]);
    }
    return Object.keys(this.sections);
  }
}

// ---------------------------------------------------------------------
// Firewall Policy, Interface & Virtual IP (VIP) Helpers
// ---------------------------------------------------------------------

function getKnownWanInterfaces(tokenizer, text) {
  const wanSet = new Set();

  if (tokenizer) {
    const intfEntries = tokenizer.getEntries("system interface");
    for (const [key, entry] of Object.entries(intfEntries)) {
      const origName = entry.name || entry._origKey || key;
      const role = (entry.properties["role"] || "").toLowerCase();
      const alias = (entry.properties["alias"] || "").toLowerCase();
      const lowerKey = key.toLowerCase();
      const lowerName = origName.toLowerCase();

      if (
        role === "wan" ||
        /\b(wan|isp|internet|external|outside)\b/i.test(alias) ||
        /\b(wan|isp|internet|external|outside)\b/i.test(lowerKey) ||
        /\b(wan|isp|internet|external|outside)\b/i.test(lowerName) ||
        lowerName.startsWith("wan") ||
        lowerKey.startsWith("wan")
      ) {
        wanSet.add(lowerName);
        wanSet.add(lowerKey);
      }
    }
  }

  if (text) {
    const secMatch = /(?:config\s+system\s+interface|show\s+system\s+interface)([\s\S]*?)(?:^end|\n\s*end)/im.exec(text);
    if (secMatch) {
      const blockRe = /edit\s+(?:"([^"]+)"|(\S+))([\s\S]*?)next/gi;
      let m;
      while ((m = blockRe.exec(secMatch[1])) !== null) {
        const name = (m[1] || m[2]).toLowerCase();
        const body = m[3];
        const roleM = /set\s+role\s+(\S+)/i.exec(body);
        const aliasM = /set\s+alias\s+(?:"([^"]+)"|(\S+))/i.exec(body);
        const role = roleM ? roleM[1].toLowerCase() : "";
        const alias = aliasM ? (aliasM[1] || aliasM[2]).toLowerCase() : "";

        if (
          role === "wan" ||
          /\b(wan|isp|internet|external|outside)\b/i.test(alias) ||
          /\b(wan|isp|internet|external|outside)\b/i.test(name) ||
          name.startsWith("wan")
        ) {
          wanSet.add(name);
        }
      }
    }
  }

  return wanSet;
}

function isWanInterface(intfName, wanSet) {
  const lower = (intfName || "").toLowerCase().trim();
  if (wanSet && wanSet.has(lower)) return true;
  return (
    lower.startsWith("wan") ||
    /\b(wan|isp|internet|external|outside)\b/i.test(lower) ||
    lower === "any"
  );
}

// ---------------------------------------------------------------------
// Schedule One-Time & Policy Schedule Helpers
// ---------------------------------------------------------------------

function parseFortiOsScheduleDate(str, isEnd = false) {
  if (!str || typeof str !== "string") return null;
  const cleaned = str.replace(/["']/g, "").trim();
  if (!cleaned) return null;

  const dateMatch = /\b(\d{4})[/-](\d{1,2})[/-](\d{1,2})\b/.exec(cleaned);
  const timeMatch = /\b(\d{1,2}):(\d{2})(?::(\d{2}))?\b/.exec(cleaned);

  if (dateMatch) {
    const year = parseInt(dateMatch[1], 10);
    const month = parseInt(dateMatch[2], 10) - 1;
    const day = parseInt(dateMatch[3], 10);
    let hour = isEnd ? 23 : 0;
    let min = isEnd ? 59 : 0;
    let sec = isEnd ? 59 : 0;
    if (timeMatch) {
      hour = parseInt(timeMatch[1], 10);
      min = parseInt(timeMatch[2], 10);
      sec = timeMatch[3] ? parseInt(timeMatch[3], 10) : 0;
    }
    const d = new Date(year, month, day, hour, min, sec);
    return isNaN(d.getTime()) ? null : d;
  }

  const parsed = new Date(cleaned);
  return isNaN(parsed.getTime()) ? null : parsed;
}

function formatScheduleDateOnly(dateObj, rawStr) {
  if (dateObj instanceof Date && !isNaN(dateObj.getTime())) {
    const y = dateObj.getFullYear();
    const m = String(dateObj.getMonth() + 1).padStart(2, "0");
    const d = String(dateObj.getDate()).padStart(2, "0");
    return `${y}/${m}/${d}`;
  }
  const dateMatch = /\b(\d{4}[/-]\d{1,2}[/-]\d{1,2})\b/.exec(rawStr || "");
  if (dateMatch) return dateMatch[1].replace(/-/g, "/");
  return rawStr || "Expired";
}

function getFirewallScheduleOneTimeMap(tokenizer, text) {
  const scheduleMap = new Map();
  const now = new Date();

  if (tokenizer) {
    const entries = tokenizer.getEntries("firewall schedule onetime");
    for (const [key, entry] of Object.entries(entries)) {
      const origName = entry.name || entry._origKey || key;
      const startStr = cleanVal(entry.properties["start"] || "");
      const endStr = cleanVal(entry.properties["end"] || "");
      const startDate = parseFortiOsScheduleDate(startStr, false);
      const endDate = parseFortiOsScheduleDate(endStr, true);
      const isExpired = endDate ? endDate < now : false;
      const isFuture = startDate ? startDate > now : false;
      const isCurrentlyActive = (!startDate || startDate <= now) && (!endDate || endDate >= now);

      const schedObj = {
        name: origName,
        startStr,
        endStr,
        startDate,
        endDate,
        isExpired,
        isFuture,
        isCurrentlyActive,
        dateOnlyStr: formatScheduleDateOnly(endDate, endStr),
      };
      scheduleMap.set(key.toLowerCase(), schedObj);
      scheduleMap.set(origName.toLowerCase(), schedObj);
    }
  }

  if (!scheduleMap.size && text) {
    const secMatch = /(?:config\s+firewall\s+schedule\s+onetime|show\s+firewall\s+schedule\s+onetime)([\s\S]*?)(?:^end|\n\s*end)/im.exec(text);
    if (secMatch) {
      const blockRe = /edit\s+(?:"([^"]+)"|(\S+))([\s\S]*?)next/gi;
      let m;
      while ((m = blockRe.exec(secMatch[1])) !== null) {
        const name = m[1] || m[2];
        const body = m[3];
        const startM = /set\s+start\s+([^\n]+)/i.exec(body);
        const endM = /set\s+end\s+([^\n]+)/i.exec(body);
        const startStr = startM ? cleanVal(startM[1]) : "";
        const endStr = endM ? cleanVal(endM[1]) : "";
        const startDate = parseFortiOsScheduleDate(startStr, false);
        const endDate = parseFortiOsScheduleDate(endStr, true);
        const isExpired = endDate ? endDate < now : false;
        const isFuture = startDate ? startDate > now : false;
        const isCurrentlyActive = (!startDate || startDate <= now) && (!endDate || endDate >= now);

        scheduleMap.set(name.toLowerCase(), {
          name,
          startStr,
          endStr,
          startDate,
          endDate,
          isExpired,
          isFuture,
          isCurrentlyActive,
          dateOnlyStr: formatScheduleDateOnly(endDate, endStr),
        });
      }
    }
  }

  return scheduleMap;
}

function classifyPolicySchedule(policy, scheduleMap) {
  if (policy.status === "disable") {
    return {
      state: "DISABLED",
      isActive: false,
      isExpired: false,
      label: "Disabled",
      scheduleName: policy.schedule || "always",
    };
  }

  const schedName = policy.schedule || "always";
  const schedLower = schedName.toLowerCase();

  if (schedLower === "always" || !schedName) {
    return {
      state: "PERMANENTLY_ACTIVE",
      isActive: true,
      isExpired: false,
      label: "Permanently Active",
      scheduleName: "always",
    };
  }

  if (scheduleMap && scheduleMap.has(schedLower)) {
    const sObj = scheduleMap.get(schedLower);
    if (sObj.isExpired) {
      return {
        state: "EXPIRED",
        isActive: false,
        isExpired: true,
        label: "Expired (Stale Rule)",
        scheduleName: sObj.name,
        startStr: sObj.startStr,
        endStr: sObj.endStr,
        endDate: sObj.endDate,
        dateOnlyStr: sObj.dateOnlyStr,
      };
    }
    if (sObj.isFuture) {
      return {
        state: "FUTURE",
        isActive: false,
        isExpired: false,
        label: "Future Scheduled",
        scheduleName: sObj.name,
        startStr: sObj.startStr,
        endStr: sObj.endStr,
        endDate: sObj.endDate,
        dateOnlyStr: sObj.dateOnlyStr,
      };
    }
    return {
      state: "CURRENTLY_ACTIVE",
      isActive: true,
      isExpired: false,
      label: "Currently Active (Temporary Travel Window)",
      scheduleName: sObj.name,
      startStr: sObj.startStr,
      endStr: sObj.endStr,
      endDate: sObj.endDate,
      dateOnlyStr: sObj.dateOnlyStr,
    };
  }

  return {
    state: "ACTIVE_OTHER",
    isActive: true,
    isExpired: false,
    label: `Active (${schedName})`,
    scheduleName: schedName,
  };
}

function getFirewallPolicyList(tokenizer, text) {
  const policyList = [];

  if (tokenizer) {
    const vdoms = tokenizer.getAllVdoms();
    for (const vdom of vdoms) {
      const entries = tokenizer.getEntries("firewall policy", vdom);
      for (const [id, entry] of Object.entries(entries)) {
        const status = cleanVal(entry.properties["status"] || "enable").toLowerCase();
        const schedule = cleanVal(entry.properties["schedule"] || "always");
        policyList.push({
          id,
          vdom,
          displayName: vdom !== "root" ? `[VDOM: ${vdom}] Policy ${id}` : `Policy ${id}`,
          name: cleanVal(entry.properties["name"] || ""),
          status,
          action: cleanVal(entry.properties["action"] || "accept").toLowerCase(),
          schedule,
          srcintf: extractQuotedTokens(entry.properties["srcintf"] || ""),
          dstintf: extractQuotedTokens(entry.properties["dstintf"] || ""),
          srcaddr: extractQuotedTokens(entry.properties["srcaddr"] || ""),
          dstaddr: extractQuotedTokens(entry.properties["dstaddr"] || ""),
          service: extractQuotedTokens(entry.properties["service"] || ""),
          groups: extractQuotedTokens(entry.properties["groups"] || ""),
          utmStatus: cleanVal(entry.properties["utm-status"] || "").toLowerCase(),
          sslProfile: cleanVal(entry.properties["ssl-ssh-profile"] || ""),
          avProfile: cleanVal(entry.properties["av-profile"] || ""),
          rawProps: entry.properties,
        });
      }
    }
  }

  if (!policyList.length && text) {
    const secMatch = /(?:config\s+firewall\s+policy|show\s+firewall\s+policy)([\s\S]*?)(?:^end|\n\s*end)/im.exec(text);
    const scopeText = secMatch ? secMatch[1] : text;
    const blockRe = /edit\s+(\d+)[\s\S]*?next/gi;
    let m;
    while ((m = blockRe.exec(scopeText)) !== null) {
      const b = m[0];
      const nameM = /set\s+name\s+(?:"([^"]+)"|(\S+))/i.exec(b);
      const statusM = /set\s+status\s+(\S+)/i.exec(b);
      const actM = /set\s+action\s+(\S+)/i.exec(b);
      const schedM = /set\s+schedule\s+(?:"([^"]+)"|(\S+))/i.exec(b);
      const schedule = schedM ? (schedM[1] || schedM[2]) : "always";
      const srcintfM = /set\s+srcintf\s+([^\n]+)/i.exec(b);
      const dstintfM = /set\s+dstintf\s+([^\n]+)/i.exec(b);
      const srcM = /set\s+srcaddr\s+([^\n]+)/i.exec(b);
      const dstM = /set\s+dstaddr\s+([^\n]+)/i.exec(b);
      const srvM = /set\s+service\s+([^\n]+)/i.exec(b);
      const grpM = /set\s+groups\s+([^\n]+)/i.exec(b);
      const utmM = /set\s+utm-status\s+(\S+)/i.exec(b);

      policyList.push({
        id: m[1],
        vdom: "root",
        displayName: `Policy ${m[1]}`,
        name: nameM ? (nameM[1] || nameM[2]) : "",
        status: statusM ? statusM[1].toLowerCase() : "enable",
        action: actM ? actM[1].toLowerCase() : "accept",
        schedule,
        srcintf: srcintfM ? extractQuotedTokens(srcintfM[1]) : [],
        dstintf: dstintfM ? extractQuotedTokens(dstintfM[1]) : [],
        srcaddr: srcM ? extractQuotedTokens(srcM[1]) : [],
        dstaddr: dstM ? extractQuotedTokens(dstM[1]) : [],
        service: srvM ? extractQuotedTokens(srvM[1]) : [],
        groups: grpM ? extractQuotedTokens(grpM[1]) : [],
        utmStatus: utmM ? utmM[1].toLowerCase() : "",
      });
    }
  }

  const scheduleMap = getFirewallScheduleOneTimeMap(tokenizer, text);
  for (const pol of policyList) {
    pol.schedInfo = classifyPolicySchedule(pol, scheduleMap);
  }

  return policyList;
}

function getFirewallVipList(tokenizer, text) {
  const vipList = [];

  if (tokenizer) {
    const vdoms = tokenizer.getAllVdoms();
    for (const vdom of vdoms) {
      const entries = tokenizer.getEntries("firewall vip", vdom);
      for (const [name, entry] of Object.entries(entries)) {
        const portforward = cleanVal(entry.properties["portforward"] || "disable").toLowerCase();
        const type = cleanVal(entry.properties["type"] || "").toLowerCase();
        vipList.push({
          name,
          vdom,
          displayName: vdom !== "root" ? `[VDOM: ${vdom}] VIP '${name}'` : `VIP '${name}'`,
          extip: cleanVal(entry.properties["extip"] || ""),
          mappedip: cleanVal(entry.properties["mappedip"] || ""),
          extport: cleanVal(entry.properties["extport"] || ""),
          mappedport: cleanVal(entry.properties["mappedport"] || ""),
          portforward,
          isPortForwardEnabled: portforward === "enable",
          type,
          rawProps: entry.properties,
        });
      }
    }
  }

  if (!vipList.length && text) {
    const vipSecMatch = /(?:config\s+firewall\s+vip|show\s+firewall\s+vip)([\s\S]*?)(?:^end|\n\s*end)/im.exec(text);
    if (vipSecMatch) {
      const blockRe = /edit\s+(?:"([^"]+)"|(\S+))([\s\S]*?)next/gi;
      let m;
      while ((m = blockRe.exec(vipSecMatch[1])) !== null) {
        const name = m[1] || m[2];
        const body = m[3];
        const pfMatch = /set\s+portforward\s+(\S+)/i.exec(body);
        const portforward = pfMatch ? pfMatch[1].toLowerCase() : "disable";
        const typeMatch = /set\s+type\s+(\S+)/i.exec(body);
        const type = typeMatch ? typeMatch[1].toLowerCase() : "";
        const extportMatch = /set\s+extport\s+(\S+)/i.exec(body);
        const extport = extportMatch ? extportMatch[1].trim() : "";
        const mappedportMatch = /set\s+mappedport\s+(\S+)/i.exec(body);
        const mappedport = mappedportMatch ? mappedportMatch[1].trim() : "";
        vipList.push({
          name,
          vdom: "root",
          displayName: `VIP '${name}'`,
          extport,
          mappedport,
          portforward,
          isPortForwardEnabled: portforward === "enable",
          type,
          rawProps: { type, extport, mappedport },
        });
      }
    }
  }

  return vipList;
}

function getFirewallProxyPolicyList(tokenizer, text = "") {
  const list = [];
  if (tokenizer) {
    const vdoms = tokenizer.getAllVdoms();
    for (const vdom of vdoms) {
      const entries = tokenizer.getEntries("firewall proxy-policy", vdom);
      for (const [id, entry] of Object.entries(entries)) {
        list.push({
          id,
          vdom,
          name: cleanVal(entry.properties["name"] || ""),
          accessProxy: extractQuotedTokens(entry.properties["access-proxy"] || ""),
          dstaddr: extractQuotedTokens(entry.properties["dstaddr"] || ""),
          server: extractQuotedTokens(entry.properties["server"] || ""),
          poolName: extractQuotedTokens(entry.properties["pool-name"] || ""),
          status: cleanVal(entry.properties["status"] || "enable").toLowerCase(),
          rawProps: entry.properties,
        });
      }
    }
  }

  if (!list.length && text) {
    const secMatch = /(?:config\s+firewall\s+proxy-policy|show\s+firewall\s+proxy-policy)([\s\S]*?)(?:^end|\n\s*end)/im.exec(text);
    if (secMatch) {
      const blockRe = /edit\s+(\d+|\S+)([\s\S]*?)next/gi;
      let m;
      while ((m = blockRe.exec(secMatch[1])) !== null) {
        const id = m[1];
        const body = m[2];
        const apMatch = /set\s+access-proxy\s+([^\n]+)/i.exec(body);
        const dstMatch = /set\s+dstaddr\s+([^\n]+)/i.exec(body);
        const srvMatch = /set\s+server\s+([^\n]+)/i.exec(body);
        const poolMatch = /set\s+pool-name\s+([^\n]+)/i.exec(body);
        const statusMatch = /set\s+status\s+(\S+)/i.exec(body);
        list.push({
          id,
          vdom: "root",
          name: id,
          accessProxy: apMatch ? extractQuotedTokens(apMatch[1]) : [],
          dstaddr: dstMatch ? extractQuotedTokens(dstMatch[1]) : [],
          server: srvMatch ? extractQuotedTokens(srvMatch[1]) : [],
          poolName: poolMatch ? extractQuotedTokens(poolMatch[1]) : [],
          status: statusMatch ? statusMatch[1].toLowerCase() : "enable",
          rawProps: {},
        });
      }
    }
  }
  return list;
}

function getFirewallAccessProxyList(tokenizer, text = "") {
  const list = [];
  if (tokenizer) {
    const vdoms = tokenizer.getAllVdoms();
    for (const vdom of vdoms) {
      const entries = tokenizer.getEntries("firewall access-proxy", vdom);
      for (const [name, entry] of Object.entries(entries)) {
        list.push({
          name,
          vdom,
          rawProps: entry.properties,
        });
      }
    }
  }
  if (!list.length && text) {
    const secMatch = /(?:config\s+firewall\s+access-proxy|show\s+firewall\s+access-proxy)([\s\S]*?)(?:^end|\n\s*end)/im.exec(text);
    if (secMatch) {
      const blockRe = /edit\s+(?:"([^"]+)"|(\S+))([\s\S]*?)next/gi;
      let m;
      while ((m = blockRe.exec(secMatch[1])) !== null) {
        const name = m[1] || m[2];
        list.push({
          name,
          vdom: "root",
          rawProps: {},
        });
      }
    }
  }
  return list;
}

/**
 * SEC-VIP-01: Virtual IP (VIP) to Policy Correlation & Port Forwarding
 * Section: config firewall vip & config firewall policy
 * Cross-reference unforwarded VIPs with active firewall policies and ZTNA access proxies:
 * - FAIL (Critical Exposure): Active policy permits traffic (action accept) from WAN with service "ALL".
 * - WARN (Mitigated Exposure): Active policy restricts service to specific ports.
 * - ZTNA (Active ZTNA Proxy): Bound to ZTNA access proxy architecture.
 * - INFO (Dormant VIP): VIP is not bound to any active firewall or proxy policy.
 * - PASS: All configured VIPs enforce port forwarding or active ZTNA architecture.
 */
function checkSecVirtualIps(tokenizer, text = "") {
  const vipList = getFirewallVipList(tokenizer, text);
  const hasVipSection = tokenizer ? !!tokenizer.getSection("firewall vip") : /(?:config|show)\s+firewall\s+vip/i.test(text);
  if (!vipList.length && !hasVipSection) return null;
  if (!vipList.length) return null;

  const src = tokenizer ? "conf" : "cli";
  const unforwardedVips = vipList.filter((v) => !v.isPortForwardEnabled);

  if (!unforwardedVips.length) {
    return makeFinding(
      "SEC-VIP-01",
      "Virtual IP (VIP) Port Forwarding",
      "PASS",
      `All ${vipList.length} configured Virtual IP(s) enforce explicit port forwarding restrictions.`,
      "",
      "",
      "Security & Hardening",
      src
    );
  }

  const proxyPolicyList = getFirewallProxyPolicyList(tokenizer, text);
  const accessProxyList = getFirewallAccessProxyList(tokenizer, text);

  // Build references for ZTNA
  const ztnaRefNames = new Set();
  for (const pp of proxyPolicyList) {
    pp.accessProxy.forEach((n) => ztnaRefNames.add(n.toLowerCase()));
    pp.dstaddr.forEach((n) => ztnaRefNames.add(n.toLowerCase()));
    pp.server.forEach((n) => ztnaRefNames.add(n.toLowerCase()));
    pp.poolName.forEach((n) => ztnaRefNames.add(n.toLowerCase()));
  }
  for (const ap of accessProxyList) {
    ztnaRefNames.add(ap.name.toLowerCase());
  }

  const ztnaList = [];
  const standardUnforwardedVips = [];

  for (const vip of unforwardedVips) {
    const vipLower = vip.name.toLowerCase();

    // Check if this is a ZTNA Server object:
    // 1. props["type"] === "access-proxy"
    // 2. Referenced in firewall proxy-policy (e.g. set access-proxy or set server)
    // 3. Name starts with ZTNA_ or ztna-
    const isZtnaType = vip.type === "access-proxy" || (vip.rawProps && vip.rawProps["type"] === "access-proxy");
    const isZtnaNamed = /^ztna[_-]/i.test(vip.name);
    const isZtnaBound = ztnaRefNames.has(vipLower);

    if (isZtnaType || isZtnaNamed || isZtnaBound) {
      const extPort = vip.extport || (vip.rawProps && (vip.rawProps["extport"] || vip.rawProps["mappedport"])) || "default";
      ztnaList.push({
        name: vip.name,
        extport: extPort,
        details: "Mapped to ZTNA Proxy Architecture"
      });
    } else {
      standardUnforwardedVips.push(vip);
    }
  }

  if (!standardUnforwardedVips.length && ztnaList.length > 0) {
    const ztnaBullets = ztnaList
      .map((z) => `  • ZTNA Access Proxy: '${z.name}' (Port ${z.extport || "default"} -> Mapped to ZTNA Proxy Architecture)`)
      .join("\n");
    return makeFinding(
      "SEC-VIP-01",
      "Virtual IP (VIP) Port Forwarding",
      "PASS",
      `All ${vipList.length} configured Virtual IP(s) enforce explicit port forwarding or operate as active ZTNA Access Proxy servers:\n\nZTNA Proxy Server Objects (${ztnaList.length}):\n${ztnaBullets}`,
      "",
      "",
      "Security & Hardening",
      src
    );
  }

  const policyList = getFirewallPolicyList(tokenizer, text);
  const hasPolicySection = tokenizer ? !!tokenizer.getSection("firewall policy") : /(?:config|show)\s+firewall\s+policy/i.test(text);

  if (!policyList.length && !hasPolicySection) {
    const names = standardUnforwardedVips.map((v) => `'${v.name}'`).join(", ");
    const ztnaSection = ztnaList.length > 0
      ? `\n\nZTNA Proxy Server Objects (${ztnaList.length} VIP${ztnaList.length > 1 ? "s" : ""}):\n` +
        ztnaList.map((z) => `  • ZTNA Access Proxy: '${z.name}' (Port ${z.extport || "default"} -> Mapped to ZTNA Proxy Architecture)`).join("\n")
      : "";
    return makeFinding(
      "SEC-VIP-01",
      "Virtual IP (VIP) Port Forwarding",
      "WARN",
      `${standardUnforwardedVips.length} Virtual IP(s) configured without port forwarding (${names}). Policy binding could not be verified (firewall policy section missing).${ztnaSection}`,
      "Enable portforward ('set portforward enable', 'set extport ...', 'set mappedport ...') on VIPs to restrict access strictly to required service ports.",
      `config firewall vip\n    edit "${standardUnforwardedVips[0].name}"\n        set portforward enable\n        set extport <port>\n        set mappedport <port>\n    next\nend`,
      "Security & Hardening",
      src
    );
  }

  const activePolicies = policyList.filter((p) => {
    if (p.status === "disable") return false;
    if (p.schedInfo && p.schedInfo.isExpired) return false;
    return true;
  });
  const wanSet = getKnownWanInterfaces(tokenizer, text);

  const failList = [];
  const warnList = [];
  const infoList = [];

  for (const vip of standardUnforwardedVips) {
    const vipLower = vip.name.toLowerCase();

    const referencing = activePolicies.filter((p) =>
      p.dstaddr.some((addr) => addr.toLowerCase() === vipLower)
    );

    if (!referencing.length) {
      const allReferencing = policyList.filter((p) =>
        p.dstaddr.some((addr) => addr.toLowerCase() === vipLower)
      );
      const expiredRef = allReferencing.filter((p) => p.schedInfo && p.schedInfo.isExpired);
      if (expiredRef.length > 0) {
        infoList.push({
          vip: `${vip.name} (Policy ${expiredRef.map((p) => p.id).join(", ")} schedule expired: ${expiredRef.map((p) => p.schedInfo.scheduleName).join(", ")})`,
        });
      } else {
        infoList.push({
          vip: vip.name,
        });
      }
      continue;
    }

    const critPol = referencing.find((p) => {
      if (p.action !== "accept") return false;
      const isWan = p.srcintf.some((intf) => isWanInterface(intf, wanSet));
      if (!isWan) return false;
      return p.service.some((s) => s.toLowerCase() === "all");
    });

    if (critPol) {
      failList.push({
        vip: vip.name,
        policyId: critPol.id,
      });
      continue;
    }

    const wanPol = referencing.find((p) => {
      if (p.action !== "accept") return false;
      return p.srcintf.some((intf) => isWanInterface(intf, wanSet));
    });

    if (wanPol) {
      const srvStr = wanPol.service.join(", ") || "specific ports";
      warnList.push({
        vip: vip.name,
        policyId: wanPol.id,
        services: srvStr,
      });
      continue;
    }

    const intPol = referencing[0];
    const srvStr = intPol.service.join(", ") || "restricted";
    warnList.push({
      vip: vip.name,
      policyId: intPol.id,
      services: srvStr,
    });
  }

  const sections = [`Total Unforwarded VIP Objects: ${unforwardedVips.length}`];

  if (failList.length > 0) {
    sections.push(`\nCritical Exposure (${failList.length} VIP${failList.length > 1 ? "s" : ""}):`);
    failList.forEach((f) => {
      sections.push(`  • ${f.vip} -> Policy ${f.policyId} (Exposed to Internet with service: ALL)`);
    });
  }

  if (warnList.length > 0) {
    sections.push(`\nMitigated by Firewall Policy (${warnList.length} VIP${warnList.length > 1 ? "s" : ""}):`);
    warnList.forEach((w) => {
      sections.push(`  • ${w.vip} -> Policy ${w.policyId} (${w.services})`);
    });
  }

  if (ztnaList.length > 0) {
    sections.push(`\nZTNA Proxy Server Objects (${ztnaList.length} VIP${ztnaList.length > 1 ? "s" : ""}):`);
    ztnaList.forEach((z) => {
      sections.push(`  • ZTNA Access Proxy: '${z.name}' (Port ${z.extport || "default"} -> Mapped to ZTNA Proxy Architecture)`);
    });
  }

  if (infoList.length > 0) {
    sections.push(`\nDormant / Unbound VIP Objects (${infoList.length} VIP${infoList.length > 1 ? "s" : ""}):`);
    infoList.forEach((i) => {
      sections.push(`  • ${i.vip}`);
    });
  }

  const structuredFindingText = sections.join("\n");

  if (failList.length > 0) {
    const firstFail = failList[0];
    return makeFinding(
      "SEC-VIP-01",
      "Virtual IP (VIP) Port Forwarding",
      "FAIL",
      structuredFindingText,
      `Configure explicit port forwarding on exposed VIP '${firstFail.vip}' ('set portforward enable', 'set extport ...', 'set mappedport ...') or restrict Policy ${firstFail.policyId} service from ALL to required ports only.`,
      `config firewall vip\n    edit "${firstFail.vip}"\n        set portforward enable\n        set extport <external-port>\n        set mappedport <mapped-port>\n    next\nend`,
      "Security & Hardening",
      src
    );
  }

  if (warnList.length > 0) {
    const firstWarn = warnList[0];
    return makeFinding(
      "SEC-VIP-01",
      "Virtual IP (VIP) Port Forwarding",
      "WARN",
      structuredFindingText,
      `Enable explicit port forwarding on VIP '${firstWarn.vip}' at the VIP definition layer for defense-in-depth port restriction.`,
      `config firewall vip\n    edit "${firstWarn.vip}"\n        set portforward enable\n        set extport <external-port>\n        set mappedport <mapped-port>\n    next\nend`,
      "Security & Hardening",
      src
    );
  }

  if (infoList.length > 0) {
    const firstInfo = infoList[0];
    return makeFinding(
      "SEC-VIP-01",
      "Virtual IP (VIP) Port Forwarding",
      "INFO",
      structuredFindingText,
      `Audit unreferenced VIP '${firstInfo.vip}'. If obsolete or unused, remove it to maintain clean firewall configuration hygiene.`,
      `config firewall vip\n    delete "${firstInfo.vip}"\nend`,
      "Security & Hardening",
      src
    );
  }

  if (ztnaList.length > 0) {
    return makeFinding(
      "SEC-VIP-01",
      "Virtual IP (VIP) Port Forwarding",
      "PASS",
      `All ${vipList.length} configured Virtual IP(s) enforce explicit port forwarding or operate as active ZTNA Access Proxy servers:\n${structuredFindingText}`,
      "",
      "",
      "Security & Hardening",
      src
    );
  }

  return makeFinding(
    "SEC-VIP-01",
    "Virtual IP (VIP) Port Forwarding",
    "PASS",
    `All ${vipList.length} configured Virtual IP(s) enforce explicit port forwarding restrictions.`,
    "",
    "",
    "Security & Hardening",
    src
  );
}

/**
 * SEC-VPN-01: SSL VPN Geo-Fencing & Country Baseline Audit
 * Checklist Item 13: "Check SSL VPN settings for any new country added to allowed VPN access"
 * Baseline: Strictly ISRAEL (IL) / Domestic corporate static IPs.
 * Foreign countries (e.g., Turkey, Serbia, Thailand, India, UAE, Georgia, Russia, Germany, USA) must NEVER be marked as green PASS.
 * FAIL: Global unconstrained access ('all' / unset) OR High-Risk foreign origin + unrestricted internal policy (dstaddr 'all').
 * WARN: Any foreign country outside Israel authorized in source-address (SecOps review & client notification required).
 * PASS: Strictly restricted to Israel / domestic entities with zero foreign countries allowed.
 */

const HIGH_RISK_VPN_COUNTRIES = {
  TR: "Turkey",
  TUR: "Turkey",
  RU: "Russia",
  RUS: "Russia",
  CN: "China",
  CHN: "China",
  IR: "Iran",
  IRN: "Iran",
  AE: "UAE",
  ARE: "UAE",
  UAE: "UAE",
  IN: "India",
  IND: "India",
  TH: "Thailand",
  THA: "Thailand",
  RS: "Serbia",
  SRB: "Serbia",
  GE: "Georgia",
  GEO: "Georgia",
  ME: "Montenegro",
  MNE: "Montenegro",
  UA: "Ukraine",
  UKR: "Ukraine",
  BY: "Belarus",
  BLR: "Belarus",
  KP: "North Korea",
  PRK: "North Korea",
  SY: "Syria",
  SYR: "Syria",
  BR: "Brazil",
  BRA: "Brazil",
  VN: "Vietnam",
  VNM: "Vietnam",
  ID: "Indonesia",
  IDN: "Indonesia",
  PK: "Pakistan",
  PAK: "Pakistan",
  EG: "Egypt",
  EGY: "Egypt",
  SA: "Saudi Arabia",
  SAU: "Saudi Arabia",
  QA: "Qatar",
  QAT: "Qatar",
  JO: "Jordan",
  JOR: "Jordan",
  LB: "Lebanon",
  LBN: "Lebanon",
  IQ: "Iraq",
  IRQ: "Iraq",
  YE: "Yemen",
  YEM: "Yemen",
  AF: "Afghanistan",
  AFG: "Afghanistan",
  ZA: "South Africa",
  ZAF: "South Africa",
  NG: "Nigeria",
  NGA: "Nigeria",
  CO: "Colombia",
  COL: "Colombia",
  MX: "Mexico",
  MEX: "Mexico",
};

const GENERAL_FOREIGN_VPN_COUNTRIES = {
  US: "United States",
  USA: "United States",
  GB: "United Kingdom",
  GBR: "United Kingdom",
  UK: "United Kingdom",
  DE: "Germany",
  DEU: "Germany",
  FR: "France",
  FRA: "France",
  IT: "Italy",
  ITA: "Italy",
  CY: "Cyprus",
  CYP: "Cyprus",
  GR: "Greece",
  GRC: "Greece",
  ES: "Spain",
  ESP: "Spain",
  PT: "Portugal",
  PRT: "Portugal",
  NL: "Netherlands",
  NLD: "Netherlands",
  BE: "Belgium",
  BEL: "Belgium",
  CH: "Switzerland",
  CHE: "Switzerland",
  AT: "Austria",
  AUT: "Austria",
  PL: "Poland",
  POL: "Poland",
  CZ: "Czech Republic",
  CZE: "Czech Republic",
  DK: "Denmark",
  DNK: "Denmark",
  NO: "Norway",
  NOR: "Norway",
  SE: "Sweden",
  SWE: "Sweden",
  FI: "Finland",
  FIN: "Finland",
  IE: "Ireland",
  IRL: "Ireland",
  RO: "Romania",
  ROU: "Romania",
  BG: "Bulgaria",
  BGR: "Bulgaria",
  HU: "Hungary",
  HUN: "Hungary",
  SC: "Seychelles",
  SYC: "Seychelles",
  CA: "Canada",
  CAN: "Canada",
  AU: "Australia",
  AUS: "Australia",
  JP: "Japan",
  JPN: "Japan",
  KR: "South Korea",
  KOR: "South Korea",
  SG: "Singapore",
  SGP: "Singapore",
  HK: "Hong Kong",
  HKG: "Hong Kong",
  TW: "Taiwan",
  TWN: "Taiwan",
  NZ: "New Zealand",
  NZL: "New Zealand",
  HR: "Croatia",
  HRV: "Croatia",
  SK: "Slovakia",
  SVK: "Slovakia",
  SI: "Slovenia",
  SVN: "Slovenia",
  LT: "Lithuania",
  LTU: "Lithuania",
  LV: "Latvia",
  LVA: "Latvia",
  EE: "Estonia",
  EST: "Estonia",
  LU: "Luxembourg",
  LUX: "Luxembourg",
  MT: "Malta",
  MLT: "Malta",
  IS: "Iceland",
  ISL: "Iceland",
  AR: "Argentina",
  ARG: "Argentina",
  CL: "Chile",
  CHL: "Chile",
  MY: "Malaysia",
  MYS: "Malaysia",
  PH: "Philippines",
  PHL: "Philippines",
  CR: "Costa Rica",
  CRI: "Costa Rica",
  PA: "Panama",
  PAN: "Panama",
  UY: "Uruguay",
  URY: "Uruguay",
  MA: "Morocco",
  MAR: "Morocco",
};

const KNOWN_COUNTRY_NAMES = {
  austria: "Austria",
  hungary: "Hungary",
  seychelles: "Seychelles",
  sweden: "Sweden",
  switzerland: "Switzerland",
  france: "France",
  germany: "Germany",
  italy: "Italy",
  spain: "Spain",
  portugal: "Portugal",
  netherlands: "Netherlands",
  belgium: "Belgium",
  cyprus: "Cyprus",
  greece: "Greece",
  poland: "Poland",
  denmark: "Denmark",
  norway: "Norway",
  finland: "Finland",
  ireland: "Ireland",
  romania: "Romania",
  bulgaria: "Bulgaria",
  canada: "Canada",
  australia: "Australia",
  japan: "Japan",
  singapore: "Singapore",
  hongkong: "Hong Kong",
  taiwan: "Taiwan",
  newzealand: "New Zealand",
  croatia: "Croatia",
  slovakia: "Slovakia",
  slovenia: "Slovenia",
  lithuania: "Lithuania",
  latvia: "Latvia",
  estonia: "Estonia",
  luxembourg: "Luxembourg",
  malta: "Malta",
  iceland: "Iceland",
  turkey: "Turkey",
  russia: "Russia",
  china: "China",
  iran: "Iran",
  uae: "UAE",
  india: "India",
  thailand: "Thailand",
  serbia: "Serbia",
  georgia: "Georgia",
  montenegro: "Montenegro",
  ukraine: "Ukraine",
  belarus: "Belarus",
  usa: "USA",
  uk: "United Kingdom",
};

const HIGH_RISK_VPN_TOKENS = new Set([
  "turkey", "turkiye", "türkiye", "turkish", "tr", "tur",
  "russia", "russian", "ru", "rus",
  "china", "chinese", "cn", "chn",
  "iran", "iranian", "ir", "irn",
  "emirates", "dubai", "uae", "ae", "are", "abudhabi",
  "india", "indian", "in", "ind",
  "thailand", "thai", "th", "tha",
  "serbia", "serbian", "rs", "srb",
  "georgia", "georgian", "ge", "geo",
  "montenegro", "me", "mne",
  "ukraine", "ukrainian", "ua", "ukr",
  "belarus", "belarusian", "by", "blr",
  "korea", "kp", "prk",
  "syria", "syrian", "sy", "syr",
  "brazil", "brazilian", "br", "bra",
  "vietnam", "vietnamese", "vn", "vnm",
  "indonesia", "indonesian", "id", "idn",
  "pakistan", "pakistani", "pk", "pak",
  "egypt", "egyptian", "eg", "egy",
  "saudi", "ksa", "sa", "sau",
  "qatar", "qatari", "qa", "qat",
  "jordan", "jordanian", "jo", "jor",
  "lebanon", "lebanese", "lb", "lbn",
  "iraq", "iraqi", "iq", "irq",
  "yemen", "yemeni", "ye", "yem",
  "afghanistan", "af", "afg",
  "southafrica", "za", "zaf",
  "nigeria", "nigerian", "ng", "nga",
  "colombia", "colombian", "co", "col",
  "mexico", "mexican", "mx", "mex",
]);

const GENERAL_FOREIGN_VPN_TOKENS = new Set([
  "usa", "us", "america", "unitedstates",
  "uk", "gb", "gbr", "england", "britain", "unitedkingdom",
  "germany", "deutschland", "german", "de", "deu",
  "france", "french", "fr", "fra",
  "italy", "italia", "italian", "it", "ita",
  "cyprus", "cypriot", "cy", "cyp",
  "greece", "greek", "gr", "grc",
  "spain", "spanish", "es", "esp",
  "portugal", "portuguese", "pt", "prt",
  "netherlands", "holland", "dutch", "nl", "nld",
  "belgium", "belgian", "be", "bel",
  "switzerland", "swiss", "ch", "che",
  "austria", "austrian", "at", "aut",
  "poland", "polish", "pl", "pol",
  "czech", "czechia", "cz", "cze",
  "denmark", "danish", "dk", "dnk",
  "norway", "norwegian", "no", "nor",
  "sweden", "swedish", "se", "swe",
  "finland", "finnish", "fi", "fin",
  "ireland", "irish", "ie", "irl",
  "romania", "romanian", "ro", "rou",
  "bulgaria", "bulgarian", "bg", "bgr",
  "hungary", "hungarian", "hu", "hun",
  "seychelles", "seychellois", "sc", "syc",
  "canada", "canadian", "ca", "can",
  "australia", "australian", "au", "aus",
  "japan", "japanese", "jp", "jpn",
  "korea", "southkorea", "kr", "kor",
  "singapore", "singaporean", "sg", "sgp",
  "hongkong", "hk", "hkg",
  "taiwan", "taiwanese", "tw", "twn",
  "newzealand", "nz", "nzl",
  "croatia", "croatian", "hr", "hrv",
  "slovakia", "slovak", "sk", "svk",
  "slovenia", "slovenian", "si", "svn",
  "lithuania", "lithuanian", "lt", "ltu",
  "latvia", "latvian", "lv", "lva",
  "estonia", "estonian", "ee", "est",
  "luxembourg", "lu", "lux",
  "malta", "maltese", "mt", "mlt",
  "iceland", "icelandic", "is", "isl",
  "argentina", "argentine", "ar", "arg",
  "chile", "chilean", "cl", "chl",
  "morocco", "moroccan", "ma", "mar",
  "malaysia", "malaysian", "my", "mys",
  "philippines", "filipino", "ph", "phl",
]);

const DOMESTIC_VPN_TOKENS = new Set([
  "israel", "il", "isr", "local", "corp", "office", "internal", "lan", "hq", "domestic",
  "branch", "site", "allowed", "vpn", "allowed-vpn", "allowed_vpn", "vpn-allowed", "vpn_allowed",
]);

const ISO_COUNTRY_NAMES = {
  ...HIGH_RISK_VPN_COUNTRIES,
  ...GENERAL_FOREIGN_VPN_COUNTRIES,
  IL: "Israel",
  ISR: "Israel",
};

function getIsoCountryName(code) {
  if (!code) return "";
  const upper = code.trim().toUpperCase();
  return ISO_COUNTRY_NAMES[upper] || upper;
}

function getFirewallAddressMap(tokenizer, text, targetVdom = null) {
  const map = new Map();
  if (tokenizer) {
    const vdomEntries = targetVdom ? (tokenizer.getEntries("firewall address", targetVdom) || {}) : (tokenizer.getEntries("firewall address") || {});
    const rootEntries = (targetVdom && targetVdom !== "root") ? (tokenizer.getEntries("firewall address", "root") || {}) : {};
    const allEntries = { ...rootEntries, ...vdomEntries };
    for (const [key, entry] of Object.entries(allEntries)) {
      const origName = entry.name || entry._origKey || key;
      const props = entry.properties || {};
      const type = cleanVal(props["type"] || "ipmask").toLowerCase();
      const country = cleanVal(props["country"] || "").toUpperCase();
      const subnet = cleanVal(props["subnet"] || "");
      const addrObj = { name: origName, type, country, subnet };
      map.set(key.toLowerCase(), addrObj);
      map.set(origName.toLowerCase(), addrObj);
    }
  }

  if (!map.size && text) {
    const secMatches = [...text.matchAll(/(?:config|show)\s+firewall\s+address([\s\S]*?)(?:^end|\n\s*end)/gim)];
    for (const secMatch of secMatches) {
      const blockRe = /edit\s+(?:"([^"]+)"|(\S+))([\s\S]*?)next/gi;
      let m;
      while ((m = blockRe.exec(secMatch[1])) !== null) {
        const name = m[1] || m[2];
        const body = m[3];
        const typeM = /set\s+type\s+(\S+)/i.exec(body);
        const countryM = /set\s+country\s+(?:"([^"]+)"|(\S+))/i.exec(body);
        const subnetM = /set\s+subnet\s+([^\n]+)/i.exec(body);
        map.set(name.toLowerCase(), {
          name,
          type: typeM ? typeM[1].toLowerCase() : "ipmask",
          country: countryM ? (countryM[1] || countryM[2]).toUpperCase() : "",
          subnet: subnetM ? subnetM[1].trim() : "",
        });
      }
    }
  }
  return map;
}

function getFirewallAddrGroupMap(tokenizer, text, targetVdom = null) {
  const map = new Map();
  if (tokenizer) {
    const vdomEntries = targetVdom ? (tokenizer.getEntries("firewall addrgrp", targetVdom) || {}) : (tokenizer.getEntries("firewall addrgrp") || {});
    const rootEntries = (targetVdom && targetVdom !== "root") ? (tokenizer.getEntries("firewall addrgrp", "root") || {}) : {};
    const allEntries = { ...rootEntries, ...vdomEntries };
    for (const [key, entry] of Object.entries(allEntries)) {
      const origName = entry.name || entry._origKey || key;
      const props = entry.properties || {};
      const members = extractQuotedTokens(props["member"] || "");
      const grpObj = { name: origName, members };
      map.set(key.toLowerCase(), grpObj);
      map.set(origName.toLowerCase(), grpObj);
    }
  }

  if (!map.size && text) {
    const secMatches = [...text.matchAll(/(?:config|show)\s+firewall\s+addrgrp([\s\S]*?)(?:^end|\n\s*end)/gim)];
    for (const secMatch of secMatches) {
      const blockRe = /edit\s+(?:"([^"]+)"|(\S+))([\s\S]*?)next/gi;
      let m;
      while ((m = blockRe.exec(secMatch[1])) !== null) {
        const name = m[1] || m[2];
        const body = m[3];
        const memM = /set\s+member\s+([^\n]+)/i.exec(body);
        map.set(name.toLowerCase(), {
          name,
          members: memM ? extractQuotedTokens(memM[1]) : [],
        });
      }
    }
  }
  return map;
}

function resolveAddrGroupMembersRecursive(token, grpMap, visited = new Set()) {
  const lower = token.toLowerCase();
  if (visited.has(lower)) {
    return [];
  }
  visited.add(lower);

  let grp = grpMap ? (grpMap.get(lower) || grpMap.get(`root::${lower}`)) : null;
  if (!grp && grpMap) {
    for (const [k, v] of grpMap.entries()) {
      if (k === lower || k.endsWith(`::${lower}`)) {
        grp = v;
        break;
      }
    }
  }

  if (grp && grp.members && grp.members.length > 0) {
    const leafTokens = [];
    for (const member of grp.members) {
      const resolved = resolveAddrGroupMembersRecursive(member, grpMap, new Set(visited));
      if (resolved.length > 0) {
        leafTokens.push(...resolved);
      } else {
        leafTokens.push(member);
      }
    }
    return leafTokens;
  }

  return [];
}

function classifyVpnSourceEntity(token, addrMap) {
  const lower = token.toLowerCase();
  const tokenUpper = token.toUpperCase();

  // 0. Default wildcard check
  if (lower === "all" || lower === "all_ipv4" || lower === "0.0.0.0/0") {
    return {
      token,
      isWildcard: true,
      isDomestic: false,
      isForeign: false,
      isStaticIp: false,
      countryName: "All (Global)",
      isoCode: "",
      riskLevel: "critical",
      isHeuristic: false,
      isGeoObject: false,
      geoDisplay: "",
    };
  }

  let addrObj = addrMap ? addrMap.get(lower) : null;
  if (!addrObj && addrMap) {
    addrObj = addrMap.get(`root::${lower}`);
    if (!addrObj) {
      for (const [k, v] of addrMap.entries()) {
        if (k === lower || k.endsWith(`::${lower}`)) {
          addrObj = v;
          break;
        }
      }
    }
  }

  // 1. Defined in firewall address with native geography type or country property
  if (addrObj && (addrObj.type === "geography" || addrObj.country)) {
    const cc = (addrObj.country || "").toUpperCase();
    if (cc === "IL" || cc === "ISR") {
      return {
        token,
        isWildcard: false,
        isDomestic: true,
        isForeign: false,
        isStaticIp: false,
        countryName: "Israel",
        isoCode: "IL",
        riskLevel: "domestic",
        isHeuristic: false,
        isGeoObject: true,
        geoDisplay: `${addrObj.name} (IL)`,
      };
    }
    const countryName = getIsoCountryName(cc);
    const isHigh = !!HIGH_RISK_VPN_COUNTRIES[cc];
    return {
      token,
      isWildcard: false,
      isDomestic: false,
      isForeign: true,
      isStaticIp: false,
      countryName,
      isoCode: cc,
      riskLevel: isHigh ? "high" : "general",
      isHeuristic: false,
      isGeoObject: true,
      geoDisplay: `${addrObj.name} (${cc})`,
    };
  }

  // 2. Subnet / IP range / host in addrMap
  if (addrObj && addrObj.type !== "geography" && addrObj.subnet) {
    const subnetIpMatch = /(\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?)/.exec(addrObj.subnet);
    let ipDisp = subnetIpMatch ? subnetIpMatch[1] : (addrObj.subnet || token);
    const maskMatch = /\s+(\d{1,3}(?:\.\d{1,3}){3})/.exec(addrObj.subnet);
    if (maskMatch && !ipDisp.includes("/")) {
      const mask = maskMatch[1];
      if (mask === "255.255.255.255") {
        // single host
      } else if (mask === "255.255.255.0") {
        ipDisp += "/24";
      } else if (mask === "255.255.0.0") {
        ipDisp += "/16";
      } else if (mask === "255.0.0.0") {
        ipDisp += "/8";
      }
    }
    return {
      token,
      isWildcard: false,
      isDomestic: false,
      isForeign: false,
      isStaticIp: true,
      ipDisplay: ipDisp,
      riskLevel: "static_ip",
      isHeuristic: false,
      isGeoObject: false,
      geoDisplay: "",
    };
  }

  // 3. Raw IPv4 / CIDR or named IP regex
  const ipv4Regex = /^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?$/;
  const namedIpRegex = /^(?:ip|host|ip-address|ip_address)[-_](\d{1,3}(?:\.\d{1,3}){3})/i;

  if (ipv4Regex.test(token)) {
    return {
      token,
      isWildcard: false,
      isDomestic: false,
      isForeign: false,
      isStaticIp: true,
      ipDisplay: token,
      riskLevel: "static_ip",
      isHeuristic: false,
      isGeoObject: false,
      geoDisplay: "",
    };
  }
  const namedMatch = namedIpRegex.exec(token);
  if (namedMatch) {
    return {
      token,
      isWildcard: false,
      isDomestic: false,
      isForeign: false,
      isStaticIp: true,
      ipDisplay: namedMatch[1],
      riskLevel: "static_ip",
      isHeuristic: false,
      isGeoObject: false,
      geoDisplay: "",
    };
  }

  // 4. Exact domestic match
  if (DOMESTIC_VPN_TOKENS.has(lower) || tokenUpper === "IL" || tokenUpper === "ISR") {
    return {
      token,
      isWildcard: false,
      isDomestic: true,
      isForeign: false,
      isStaticIp: false,
      countryName: "Israel",
      isoCode: "IL",
      riskLevel: "domestic",
      isHeuristic: false,
      isGeoObject: true,
      geoDisplay: `${token} (IL)`,
    };
  }

  // 5. Exact Country Name Match on the Full Token (Direct country address object)
  if (HIGH_RISK_VPN_COUNTRIES[tokenUpper]) {
    const cName = HIGH_RISK_VPN_COUNTRIES[tokenUpper];
    const isoCode = tokenUpper.length === 2 ? tokenUpper : (Object.entries(HIGH_RISK_VPN_COUNTRIES).find(([, v]) => v === cName && v.length === 2)?.[0] || tokenUpper);
    return {
      token,
      isWildcard: false,
      isDomestic: false,
      isForeign: true,
      isStaticIp: false,
      countryName: cName,
      isoCode,
      riskLevel: "high",
      isHeuristic: false,
      isGeoObject: true,
      geoDisplay: `${token} (${isoCode})`,
    };
  }
  if (KNOWN_COUNTRY_NAMES[lower]) {
    const isHigh = !!HIGH_RISK_VPN_TOKENS.has(lower);
    const countryName = KNOWN_COUNTRY_NAMES[lower];
    const isoCode = tokenUpper.length === 2 ? tokenUpper : (Object.entries(ISO_COUNTRY_NAMES).find(([, v]) => v.toLowerCase() === lower && v.length === 2)?.[0] || tokenUpper);
    return {
      token,
      isWildcard: false,
      isDomestic: false,
      isForeign: true,
      isStaticIp: false,
      countryName,
      isoCode,
      riskLevel: isHigh ? "high" : "general",
      isHeuristic: false,
      isGeoObject: true,
      geoDisplay: `${token} (${isoCode})`,
    };
  }
  if (GENERAL_FOREIGN_VPN_COUNTRIES[tokenUpper]) {
    return {
      token,
      isWildcard: false,
      isDomestic: false,
      isForeign: true,
      isStaticIp: false,
      countryName: GENERAL_FOREIGN_VPN_COUNTRIES[tokenUpper],
      isoCode: tokenUpper,
      riskLevel: "general",
      isHeuristic: false,
      isGeoObject: true,
      geoDisplay: `${token} (${tokenUpper})`,
    };
  }

  // 6. Word-boundary heuristics
  const words = token.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  for (const w of words) {
    const wUpper = w.toUpperCase();
    if (HIGH_RISK_VPN_COUNTRIES[wUpper] || HIGH_RISK_VPN_TOKENS.has(w)) {
      const mapped = HIGH_RISK_VPN_COUNTRIES[wUpper] || KNOWN_COUNTRY_NAMES[w] || (w.length <= 3 ? wUpper : (w.charAt(0).toUpperCase() + w.slice(1)));
      const iso = wUpper.length === 2 ? wUpper : "";
      return {
        token,
        isWildcard: false,
        isDomestic: false,
        isForeign: true,
        isStaticIp: false,
        countryName: mapped,
        isoCode: iso || wUpper,
        riskLevel: "heuristic_suspect",
        isHeuristic: true,
        heuristicOrigin: mapped,
        isGeoObject: true,
        geoDisplay: `${token} (${iso || wUpper})`,
      };
    }
  }

  for (const w of words) {
    const wUpper = w.toUpperCase();
    if (GENERAL_FOREIGN_VPN_COUNTRIES[wUpper] || GENERAL_FOREIGN_VPN_TOKENS.has(w)) {
      const mapped = GENERAL_FOREIGN_VPN_COUNTRIES[wUpper] || KNOWN_COUNTRY_NAMES[w] || (w.length <= 3 ? wUpper : (w.charAt(0).toUpperCase() + w.slice(1)));
      const iso = wUpper.length === 2 ? wUpper : "";
      return {
        token,
        isWildcard: false,
        isDomestic: false,
        isForeign: true,
        isStaticIp: false,
        countryName: mapped,
        isoCode: iso || wUpper,
        riskLevel: "heuristic_suspect",
        isHeuristic: true,
        heuristicOrigin: mapped,
        isGeoObject: true,
        geoDisplay: `${token} (${iso || wUpper})`,
      };
    }
  }

  for (const w of words) {
    if (DOMESTIC_VPN_TOKENS.has(w)) {
      return {
        token,
        isWildcard: false,
        isDomestic: true,
        isForeign: false,
        isStaticIp: false,
        countryName: "Israel",
        isoCode: "IL",
        riskLevel: "domestic",
        isHeuristic: false,
        isGeoObject: true,
        geoDisplay: `${token} (IL)`,
      };
    }
  }

  // 7. Check if token name looks like a subnet/host
  if (/subnet|lan|net|ip|srv|host|internal|dmz|mgmt/i.test(token)) {
    return {
      token,
      isWildcard: false,
      isDomestic: false,
      isForeign: false,
      isStaticIp: true,
      ipDisplay: token,
      riskLevel: "static_ip",
      isHeuristic: false,
      isGeoObject: false,
      geoDisplay: "",
    };
  }

  // 8. Default Deny: Unrecognized name treated as Foreign
  const cleanName = token.replace(/^(?:geo|country|foreign)[-_]/i, "").trim() || token;
  const formattedName = cleanName.charAt(0).toUpperCase() + cleanName.slice(1);
  return {
    token,
    isWildcard: false,
    isDomestic: false,
    isForeign: true,
    isStaticIp: false,
    countryName: formattedName,
    isoCode: token.length === 2 ? token.toUpperCase() : "",
    riskLevel: "general",
    isHeuristic: false,
    isGeoObject: true,
    geoDisplay: token.length === 2 ? `${token} (${token.toUpperCase()})` : token,
  };
}

function buildSecVpn01ObservedState({
  configStatus,
  geoObjectsList,
  allowedCountriesStr,
  geoBypassRisk,
  riskAssessment,
  additionalBullets = [],
}) {
  const geoObjStr = geoObjectsList && geoObjectsList.length > 0 ? geoObjectsList.join(", ") : "None";
  const riskStr = (geoBypassRisk === "None" || geoBypassRisk === "Low")
    ? "None - Gateway strictly constrained to authorized domestic IP space"
    : "High - Unrestricted internet access";

  const lines = [
    `Configuration Status: ${configStatus}`,
    `Configured Geo-Objects: ${geoObjStr}`,
    `Allowed Countries: ${allowedCountriesStr}`,
    `Geo-Bypass / Leakage Risk: ${riskStr}`,
  ];

  const bullets = [];
  if (riskAssessment) {
    bullets.push(riskAssessment);
  }
  if (additionalBullets && additionalBullets.length > 0) {
    bullets.push(...additionalBullets);
  }

  for (const b of bullets) {
    lines.push(`  • ${b}`);
  }

  return lines.join("\n");
}

function bucketSslVpnPolicies(policies) {
  const wan = [];
  const rdp = [];
  const smb = [];
  const mgmt = [];
  const standard = [];

  for (const p of policies) {
    const isDstAll = (p.dstaddr || []).some((a) => a.toLowerCase() === "all");
    const svcTokens = (p.service || []).map((s) => s.toLowerCase());
    const dstTokens = (p.dstaddr || []).map((d) => d.toLowerCase());
    const nameStr = (p.name || "").toLowerCase();

    // 1. WAN Breakout / Full Access
    if (isDstAll) {
      wan.push(p);
      continue;
    }

    // 2. Remote Desktop (RDP - Port 3389 / RDP)
    if (
      svcTokens.some((s) => /rdp|3389|ms-wbt-server/i.test(s)) ||
      /rdp/i.test(nameStr)
    ) {
      rdp.push(p);
      continue;
    }

    // 3. File Shares (SMB - Port 445 / 139 / SMB)
    if (
      svcTokens.some((s) => /smb|cifs|netbios|samba|445|139|microsoft-ds/i.test(s)) ||
      /smb|cifs/i.test(nameStr)
    ) {
      smb.push(p);
      continue;
    }

    // 4. Management Access (loopback, FAZ, mgmt ports 10443, 12443, 22, SSH, HTTPS)
    const isMgmtService = svcTokens.some((s) =>
      /\b(?:ssh|telnet|22|23|10443|12443|8443|fgt[-_]?admin|faz[-_]?mgmt)\b/i.test(s) ||
      s.includes("mgmt") ||
      s.includes("admin")
    );
    const isMgmtDst = dstTokens.some((d) =>
      /\b(?:loopback|faz|fortianalyzer|fgt|firewall|management|mgmt)\b/i.test(d)
    );
    const isMgmtName = /\b(?:mgmt|admin|firewall|faz|loopback)\b/i.test(nameStr);

    if (isMgmtService || isMgmtDst || isMgmtName) {
      mgmt.push(p);
      continue;
    }

    // 5. Standard Services (Aggregate remaining policies)
    standard.push(p);
  }

  return { wan, rdp, smb, mgmt, standard, total: policies.length };
}

function checkSecSslVpnGeoFencing(tokenizer, rawText = "") {
  const policyList = getFirewallPolicyList(tokenizer, rawText);
  const src = tokenizer ? "conf" : "cli";
  const remCli = "config vpn ssl settings\n    set source-address \"Israel\"\nend";

  // 1. Identify Candidate VDOMs
  let candidateVdoms = [];
  if (tokenizer) {
    candidateVdoms = tokenizer.getAllVdoms();
  } else if (rawText) {
    const vdomMatches = [...rawText.matchAll(/(?:^|\n)\s*edit\s+(?:"([^"]+)"|(\S+))/gi)];
    if (/(?:^|\n)\s*config\s+vdom\b/i.test(rawText) && vdomMatches.length > 0) {
      candidateVdoms = [...new Set(vdomMatches.map((m) => (m[1] || m[2]).toLowerCase()))];
    } else {
      candidateVdoms = ["root"];
    }
  }

  if (candidateVdoms.length === 0) {
    candidateVdoms = ["root"];
  }

  function getVdomScopeText(vdom) {
    if (!rawText) return "";
    if (candidateVdoms.length === 1 && candidateVdoms[0] === "root") return rawText;
    const vdomBlockRegex = new RegExp(`edit\\s+["']?${vdom}["']?([\\s\\S]*?)(?:next|end)`, "i");
    const m = vdomBlockRegex.exec(rawText);
    return m ? m[1] : rawText;
  }

  // 2. Scan and Filter for ACTIVE SSL-VPN VDOMs
  const activeVdomData = [];

  for (const vdom of candidateVdoms) {
    let hasVpnSec = false;
    let status = "";
    let rawSourceAddr = "";
    let rawSourceAddrNegate = "";
    const authRuleTokens = [];
    let hasAuthRules = false;
    let hasAuthRuleNegate = false;

    if (tokenizer) {
      const vpnSec = tokenizer.getSection("vpn ssl settings", vdom);
      if (vpnSec) {
        hasVpnSec = true;
        status = cleanVal(tokenizer.getProperty("vpn ssl settings", "status", vdom) || "").toLowerCase();
        rawSourceAddr = tokenizer.getProperty("vpn ssl settings", "source-address", vdom) || "";
        rawSourceAddrNegate = cleanVal(tokenizer.getProperty("vpn ssl settings", "source-address-negate", vdom) || "").toLowerCase();
      }
      const authRules =
        tokenizer.getEntries("authentication-rule", vdom) ||
        tokenizer.getEntries("vpn ssl settings::authentication-rule", vdom) ||
        (vpnSec && vpnSec.subSections && vpnSec.subSections["authentication-rule"]
          ? vpnSec.subSections["authentication-rule"].entries
          : {});
      if (authRules && Object.keys(authRules).length > 0) {
        hasAuthRules = true;
        for (const rule of Object.values(authRules)) {
          const ruleSrc = cleanVal(rule.properties?.["source-address"] || "");
          if (ruleSrc) {
            authRuleTokens.push(...extractQuotedTokens(ruleSrc));
          }
          const ruleNeg = cleanVal(rule.properties?.["source-address-negate"] || "").toLowerCase();
          if (ruleNeg === "enable") hasAuthRuleNegate = true;
        }
      }
    } else {
      const scope = getVdomScopeText(vdom);
      const vpnBlock = /(?:config|show)\s+vpn\s+ssl\s+settings([\s\S]*?)(?:^end|\n\s*end)/im.exec(scope);
      if (vpnBlock) {
        hasVpnSec = true;
        const vpnBody = vpnBlock[1];
        const sm = /set\s+status\s+(\S+)/i.exec(vpnBody);
        if (sm) status = cleanVal(sm[1]).toLowerCase();
        const am = /set\s+source-address\s+([^\n]+)/i.exec(vpnBody);
        if (am) rawSourceAddr = am[1].trim();
        const anm = /set\s+source-address-negate\s+(\S+)/i.exec(vpnBody);
        if (anm) rawSourceAddrNegate = cleanVal(anm[1]).toLowerCase();

        const ruleBlock = /config\s+authentication-rule([\s\S]*?)(?:^end|\n\s*end)/im.exec(vpnBody);
        if (ruleBlock) {
          const editRe = /edit\s+(?:\S+)([\s\S]*?)next/gi;
          let em;
          while ((em = editRe.exec(ruleBlock[1])) !== null) {
            hasAuthRules = true;
            const ram = /set\s+source-address\s+([^\n]+)/i.exec(em[1]);
            if (ram) {
              authRuleTokens.push(...extractQuotedTokens(ram[1].trim()));
            }
            const rnm = /set\s+source-address-negate\s+(\S+)/i.exec(em[1]);
            if (rnm && cleanVal(rnm[1]).toLowerCase() === "enable") hasAuthRuleNegate = true;
          }
        }
      }
    }

    const vdomPolicies = policyList.filter(
      (p) => (!p.vdom && vdom === "root") || p.vdom === vdom || candidateVdoms.length === 1
    );
    const vdomSslPolicies = vdomPolicies.filter((p) => {
      const hasSslSrc = p.srcintf.some((intf) => /ssl(?:\.root|\-vpn|\.|$)/i.test(intf));
      return hasSslSrc && p.action === "accept";
    });

    if (status === "disable") {
      continue;
    }

    if (!hasVpnSec && vdomSslPolicies.length === 0) {
      continue;
    }

    const isActive =
      status === "enable" ||
      vdomSslPolicies.length > 0 ||
      (rawSourceAddr && rawSourceAddr.trim().length > 0) ||
      hasAuthRules;

    if (!isActive) {
      continue;
    }

    activeVdomData.push({
      vdom,
      hasVpnSec,
      status,
      rawSourceAddr,
      rawSourceAddrNegate,
      authRuleTokens,
      hasAuthRules,
      hasAuthRuleNegate,
      vdomPolicies,
      vdomSslPolicies,
    });
  }

  if (activeVdomData.length === 0) {
    return null;
  }

  function evaluateActiveVdom(vdomObj) {
    const { vdom, rawSourceAddr, rawSourceAddrNegate, authRuleTokens, hasAuthRuleNegate, vdomSslPolicies } = vdomObj;

    const topTokens = rawSourceAddr ? extractQuotedTokens(rawSourceAddr) : [];
    const allTokens = [...topTokens, ...authRuleTokens];
    const isNegated = rawSourceAddrNegate === "enable" || hasAuthRuleNegate;

    // Case 1: Inverted match (source-address-negate enable)
    if (isNegated) {
      const findingText = buildSecVpn01ObservedState({
        configStatus: `Inverted Match (source-address-negate enabled with ${topTokens.join(", ") || "specified entities"})`,
        geoObjectsList: topTokens.map((t) => `${t} (Negated)`),
        allowedCountriesStr: "Global / Worldwide (All 195+ countries permitted - Negation inverts restriction)",
        geoBypassRisk: "High",
        riskAssessment: "Technical assessment: Inverted source-address negation permits connections from all global origins outside specified entities.",
        additionalBullets: [
          "Impact: Negating source-address allows any source IP worldwide to access the SSL-VPN portal, bypassing geo-fencing."
        ]
      });
      return makeFinding({
        id: "SEC-VPN-01",
        component: "SSL VPN Geo-Fencing",
        status: "FAIL",
        category: "SecOps Operational",
        source: src,
        data: { vdom, negated: true },
        findingText,
        actionText: "Disable source-address-negate and explicitly bind source-address strictly to domestic Israel IP space under config vpn ssl settings.",
        remediationCli: remCli,
      });
    }

    // Case 2: Missing or unconfigured source-address parameter
    if (topTokens.length === 0 && authRuleTokens.length === 0) {
      const findingText = buildSecVpn01ObservedState({
        configStatus: "Missing / Unset",
        geoObjectsList: [],
        allowedCountriesStr: "Global / Worldwide (All 195+ countries permitted - No geo-restriction applied)",
        geoBypassRisk: "High",
        riskAssessment: "Technical assessment: Unauthenticated global sources can reach the SSL-VPN listener directly without geo-filtering.",
        additionalBullets: [
          "Impact: SSL-VPN gateway is unconstrained and exposed to brute-force attacks, botnets, and zero-day exploit targeting worldwide."
        ]
      });
      return makeFinding({
        id: "SEC-VPN-01",
        component: "SSL VPN Geo-Fencing",
        status: "FAIL",
        category: "SecOps Operational",
        source: src,
        data: { vdom, unconfigured: true },
        findingText,
        actionText: "Configure geo-blocking address entities and restrict source-address strictly to domestic Israel IP space under config vpn ssl settings.",
        remediationCli: remCli,
      });
    }

    // Case 3: Explicit 'all' global access
    if (allTokens.some((t) => t.toLowerCase() === "all" || t.toLowerCase() === "all_ipv4")) {
      const findingText = buildSecVpn01ObservedState({
        configStatus: "Explicitly set to 'all'",
        geoObjectsList: [],
        allowedCountriesStr: "Global / Worldwide (All 195+ countries permitted - No geo-restriction applied)",
        geoBypassRisk: "High",
        riskAssessment: "Technical assessment: Gateway perimeter permits authentication handshakes from any origin worldwide.",
        additionalBullets: [
          "Impact: SSL-VPN gateway is unconstrained and exposed to brute-force attacks, botnets, and zero-day exploit targeting worldwide."
        ]
      });
      return makeFinding({
        id: "SEC-VPN-01",
        component: "SSL VPN Geo-Fencing",
        status: "FAIL",
        category: "SecOps Operational",
        source: src,
        data: { vdom, explicitAll: true },
        findingText,
        actionText: "Replace 'all' with domestic Israel country address objects ('Israel' / 'IL') to mitigate automated brute-force attacks and SSL-VPN gateway exploit scans.",
        remediationCli: remCli,
      });
    }

    // Case 4: Resolve Address Groups & Addresses Recursively
    const addrMap = getFirewallAddressMap(tokenizer, rawText, vdom);
    const grpMap = getFirewallAddrGroupMap(tokenizer, rawText, vdom);

    const expandedTokens = [];
    for (const t of allTokens) {
      const visited = new Set();
      const leafMembers = resolveAddrGroupMembersRecursive(t, grpMap, visited);
      if (leafMembers.length > 0) {
        expandedTokens.push(...leafMembers);
      } else {
        expandedTokens.push(t);
      }
    }

    const uniqueTokens = [...new Set(expandedTokens)];

    // Classify each leaf entity
    const classified = uniqueTokens.map((t) => classifyVpnSourceEntity(t, addrMap));

    // If an unwrapped group member was 'all' or wildcard
    if (classified.some((c) => c.isWildcard)) {
      const findingText = buildSecVpn01ObservedState({
        configStatus: "Explicitly set to 'all' (via address group membership)",
        geoObjectsList: [],
        allowedCountriesStr: "Global / Worldwide (All 195+ countries permitted - No geo-restriction applied)",
        geoBypassRisk: "High",
        riskAssessment: "Technical assessment: Underlying address group members contain wildcard 'all', permitting handshakes from any origin worldwide.",
        additionalBullets: [
          "Impact: SSL-VPN gateway is unconstrained and exposed to brute-force attacks, botnets, and zero-day exploit targeting worldwide."
        ]
      });
      return makeFinding({
        id: "SEC-VPN-01",
        component: "SSL VPN Geo-Fencing",
        status: "FAIL",
        category: "SecOps Operational",
        source: src,
        data: { vdom, explicitAll: true },
        findingText,
        actionText: "Remove 'all' from address groups and restrict source-address strictly to domestic Israel country address objects.",
        remediationCli: remCli,
      });
    }

    const geoEntities = classified.filter((c) => c.isGeoObject);
    const domesticEntities = classified.filter((c) => c.isDomestic);
    const foreignEntities = classified.filter((c) => c.isForeign);
    const staticIpEntities = classified.filter((c) => c.isStaticIp);

    const geoObjectsList = [...new Set(geoEntities.map((c) => c.geoDisplay || `${c.token} (${c.isoCode || c.countryName})`))];
    const domesticGeoList = [...new Set(domesticEntities.map((c) => `${c.countryName} (${c.isoCode || "IL"})`))];
    const foreignGeoList = [...new Set(foreignEntities.map((c) => `${c.countryName} (${c.isoCode || ""})`))];
    const allAllowedCountriesList = [...new Set([...domesticGeoList, ...foreignGeoList])];
    const staticIpList = [...new Set(staticIpEntities.map((c) => c.ipDisplay || c.token))];

    // Subcase 4A: Only Non-Geo IP Ranges/Subnets Configured (Zero Geo-Objects)
    if (geoEntities.length === 0 && staticIpEntities.length > 0) {
      const subnetStr = staticIpList.join(", ");
      const findingText = buildSecVpn01ObservedState({
        configStatus: `Bound to specific address objects (${allTokens.join(", ")})`,
        geoObjectsList: [],
        allowedCountriesStr: `Static Subnets Only (Non-geographic: ${subnetStr}) - Geo-Fencing not enforced`,
        geoBypassRisk: "High",
        riskAssessment: "Technical assessment: Geographic geo-fencing is not enforced at the SSL-VPN gateway; access control relies solely on static IP subnets.",
        additionalBullets: [
          `Configured Static IPs/Subnets: ${subnetStr}`,
          "SecOps Review: Geo-fencing country database is unutilized. Recommend adding domestic geographic boundary (Israel) to block unrouted/external scan probes."
        ]
      });
      return makeFinding({
        id: "SEC-VPN-01",
        component: "SSL VPN Geo-Fencing",
        status: "WARN",
        category: "SecOps Operational",
        source: src,
        data: { vdom, staticOnly: true, staticIps: staticIpList },
        findingText,
        actionText: "Incorporate domestic Israel geography address objects ('Israel' / 'IL') into source-address under config vpn ssl settings.",
        remediationCli: remCli,
      });
    }

    // Correlate with active SSL-VPN Firewall Policies
    const activeSslPolicies = vdomSslPolicies.filter(
      (p) => p.status !== "disable" && (!p.schedInfo || p.schedInfo.isActive)
    );
    const expiredSslPolicies = vdomSslPolicies.filter((p) => p.schedInfo && p.schedInfo.isExpired);
    const disabledSslPolicies = vdomSslPolicies.filter((p) => p.status === "disable");

    const activeUnrestrictedPolicies = activeSslPolicies.filter((p) => {
      const isDstAll = p.dstaddr.some((a) => a.toLowerCase() === "all");
      const isSvcAll = p.service.length === 0 || p.service.some((s) => s.toUpperCase() === "ALL");
      return isDstAll && isSvcAll;
    });
    const hasActiveUnrestrictedPolicy = activeUnrestrictedPolicies.length > 0;

    const highRiskEntities = foreignEntities.filter((c) => c.riskLevel === "high" && !c.isHeuristic);
    const heuristicEntities = foreignEntities.filter((c) => c.isHeuristic);
    const additionalForeignEntities = foreignEntities.filter((c) => c.riskLevel !== "high" && !c.isHeuristic);

    const highRiskCountryNames = [...new Set(highRiskEntities.map((c) => `${c.countryName} (${c.isoCode})`))];
    const additionalForeignCountryNames = [...new Set(additionalForeignEntities.map((c) => `${c.countryName} (${c.isoCode})`))];
    const heuristicSuspectNames = [...new Set(heuristicEntities.map((c) => `${c.token} (${c.countryName})`))];

    // Case 5: Confirmed foreign country authorized AND unrestricted internal policy
    if (foreignEntities.length > 0 && hasActiveUnrestrictedPolicy) {
      const exposingPolStr = activeUnrestrictedPolicies.map((p) => {
        const namePart = p.name ? ` ("${p.name}")` : "";
        const dstPart = p.dstaddr.join(", ");
        const svcPart = p.service.join(", ") || "ALL";
        return `Policy ID ${p.id}${namePart} -> dst: ${dstPart} (service: ${svcPart})`;
      }).join("; ");

      const bullets = [];
      if (highRiskCountryNames.length > 0) bullets.push(`High-Risk Origins: ${highRiskCountryNames.join(", ")}`);
      if (additionalForeignCountryNames.length > 0) bullets.push(`Additional Foreign Origins: ${additionalForeignCountryNames.join(", ")}`);
      if (staticIpList.length > 0) bullets.push(`Configured Static IPs/Hosts: ${staticIpList.join(", ")}`);
      bullets.push(`Exposing Firewall Policies: ${exposingPolStr}`);
      bullets.push("Destination & Scope: dstaddr 'all' | service: ALL (Full internal network access)");
      bullets.push("Impact: Direct compromise vector from foreign IP space into entire corporate network.");

      const findingText = buildSecVpn01ObservedState({
        configStatus: `Bound to specific address objects (${allTokens.join(", ")})`,
        geoObjectsList,
        allowedCountriesStr: allAllowedCountriesList.join(", "),
        geoBypassRisk: "High",
        riskAssessment: "Technical assessment: Foreign countries authorized to reach SSL-VPN listener with unrestricted internal network access (dstaddr 'all').",
        additionalBullets: bullets
      });

      return makeFinding({
        id: "SEC-VPN-01",
        component: "SSL VPN Geo-Fencing",
        status: "FAIL",
        category: "SecOps Operational",
        source: src,
        data: {
          vdom,
          highRiskCountries: highRiskCountryNames,
          additionalCountries: additionalForeignCountryNames,
          suspectHeuristics: heuristicSuspectNames,
          domesticEntities: domesticEntities.map((d) => d.token),
          staticIps: staticIpList,
          exposingPolicies: activeUnrestrictedPolicies,
        },
        findingText,
        actionText: "Immediately restrict SSL-VPN destination subnets, notify client (Checklist ID 13), and remove unauthorized foreign countries from source-address to mitigate brute-force and SSL-VPN exploit exposure.",
        remediationCli: remCli,
      });
    }

    // Case 6: Foreign Country Access Detected (outside Israel baseline)
    if (foreignEntities.length > 0) {
      if (activeSslPolicies.length === 0 && expiredSslPolicies.length > 0) {
        const expiredPolIds = expiredSslPolicies.map((p) => p.id).join(", ");
        const expiredSchedNames = [...new Set(expiredSslPolicies.map((p) => p.schedInfo.scheduleName))].join(", ");
        const expiredDates = [...new Set(expiredSslPolicies.map((p) => p.schedInfo.dateOnlyStr || p.schedInfo.endStr || "Expired"))].join(", ");

        const bullets = [];
        if (highRiskCountryNames.length > 0) bullets.push(`High-Risk Origins: ${highRiskCountryNames.join(", ")}`);
        if (additionalForeignCountryNames.length > 0) bullets.push(`Additional Foreign Origins: ${additionalForeignCountryNames.join(", ")}`);
        if (staticIpList.length > 0) bullets.push(`Configured Static IPs/Hosts: ${staticIpList.join(", ")}`);
        bullets.push(`Expired Firewall Policy: Policy ID ${expiredPolIds} with EXPIRED schedule [${expiredSchedNames}] (Expired: ${expiredDates})`);
        bullets.push("Traffic Status: Firewall blocks internal traffic (schedule expired), but VPN gateway still accepts external handshakes.");
        bullets.push(`SecOps Review: Confirm employee has concluded travel. Remove obsolete foreign country from SSL-VPN source-address and delete/archive expired policy ID [${expiredPolIds}] (Checklist ID 13).`);

        const findingText = buildSecVpn01ObservedState({
          configStatus: `Bound to specific address objects (${allTokens.join(", ")})`,
          geoObjectsList,
          allowedCountriesStr: allAllowedCountriesList.join(", "),
          geoBypassRisk: "High",
          riskAssessment: "Technical assessment: Stale Foreign Origin: Gateway listener accepts external handshakes despite expired firewall schedule.",
          additionalBullets: bullets
        });

        return makeFinding({
          id: "SEC-VPN-01",
          component: "SSL VPN Geo-Fencing",
          status: "WARN",
          category: "SecOps Operational",
          source: src,
          data: {
            vdom,
            highRiskCountries: highRiskCountryNames,
            additionalCountries: additionalForeignCountryNames,
            suspectHeuristics: heuristicSuspectNames,
            domesticEntities: domesticEntities.map((d) => d.token),
            staticIps: staticIpList,
            expiredPolicies: expiredSslPolicies,
          },
          findingText,
          actionText: `Confirm employee has concluded travel. Remove obsolete foreign country from SSL-VPN source-address and delete/archive expired policy ID [${expiredPolIds}] (Checklist ID 13).`,
          remediationCli: remCli,
        });
      }

      if (activeSslPolicies.length === 0 && disabledSslPolicies.length > 0) {
        const disabledPolIds = disabledSslPolicies.map((p) => p.id).join(", ");
        const bullets = [];
        if (highRiskCountryNames.length > 0) bullets.push(`High-Risk Origins: ${highRiskCountryNames.join(", ")}`);
        if (additionalForeignCountryNames.length > 0) bullets.push(`Additional Foreign Origins: ${additionalForeignCountryNames.join(", ")}`);
        if (staticIpList.length > 0) bullets.push(`Configured Static IPs/Hosts: ${staticIpList.join(", ")}`);
        bullets.push(`Disabled Firewall Policy: Policy ID ${disabledPolIds} (Status: disabled)`);
        bullets.push("Traffic Status: Firewall blocks internal traffic (policy disabled), but VPN gateway still accepts external handshakes.");
        bullets.push(`SecOps Review: Confirm employee has concluded travel. Remove obsolete foreign country from SSL-VPN source-address and delete/archive disabled policy ID [${disabledPolIds}] (Checklist ID 13).`);

        const findingText = buildSecVpn01ObservedState({
          configStatus: `Bound to specific address objects (${allTokens.join(", ")})`,
          geoObjectsList,
          allowedCountriesStr: allAllowedCountriesList.join(", "),
          geoBypassRisk: "High",
          riskAssessment: "Technical assessment: Stale Foreign Origin: Gateway listener accepts external handshakes despite disabled firewall policy.",
          additionalBullets: bullets
        });

        return makeFinding({
          id: "SEC-VPN-01",
          component: "SSL VPN Geo-Fencing",
          status: "WARN",
          category: "SecOps Operational",
          source: src,
          data: {
            vdom,
            highRiskCountries: highRiskCountryNames,
            additionalCountries: additionalForeignCountryNames,
            suspectHeuristics: heuristicSuspectNames,
            domesticEntities: domesticEntities.map((d) => d.token),
            staticIps: staticIpList,
            disabledPolicies: disabledSslPolicies,
          },
          findingText,
          actionText: `Confirm employee has concluded travel. Remove obsolete foreign country from SSL-VPN source-address and delete/archive disabled policy ID [${disabledPolIds}] (Checklist ID 13).`,
          remediationCli: remCli,
        });
      }

      // Active foreign policies
      const polSummaryLines = [];
      const b = bucketSslVpnPolicies(activeSslPolicies);
      if (activeSslPolicies.length > 0) {
        polSummaryLines.push(`Associated Access Scope (${activeSslPolicies.length} ${activeSslPolicies.length === 1 ? "Policy" : "Policies"}):`);
        if (b.wan.length > 0) polSummaryLines.push(`  • WAN / Full Access (dst: all): Policy [${b.wan.map((p) => p.id).join(", ")}]`);
        if (b.rdp.length > 0) polSummaryLines.push(`  • Remote Desktop (RDP): ${b.rdp.length} policy (Policy [${b.rdp.map((p) => p.id).join(", ")}])`);
        if (b.smb.length > 0) polSummaryLines.push(`  • File Shares (SMB): ${b.smb.length} policy (Policy [${b.smb.map((p) => p.id).join(", ")}])`);
        if (b.mgmt.length > 0) polSummaryLines.push(`  • Management Access: Policy [${b.mgmt.map((p) => p.id).join(", ")}]`);
        if (b.standard.length > 0) polSummaryLines.push(`  • Standard Services: ${b.standard.length} remaining policies`);
      }

      const bullets = [];
      if (highRiskCountryNames.length > 0) bullets.push(`High-Risk Origins: ${highRiskCountryNames.join(", ")}`);
      if (additionalForeignCountryNames.length > 0) bullets.push(`Additional Foreign Origins (${additionalForeignCountryNames.length}): ${additionalForeignCountryNames.join(", ")}`);
      if (heuristicSuspectNames.length > 0) {
        bullets.push(`Heuristic Suspect Objects (${heuristicSuspectNames.length}): ${heuristicSuspectNames.join(", ")}`);
        bullets.push("Operational Review: Name pattern matched country heuristic. Verify if object represents internal subnet or intended foreign access.");
      }
      if (staticIpList.length > 0) bullets.push(`Static Objects / IPs: ${staticIpList.join(", ")}`);
      bullets.push(...polSummaryLines);
      bullets.push("SecOps Review: Audit foreign origins against client authorized travel list (Checklist Item 13).");

      const findingText = buildSecVpn01ObservedState({
        configStatus: `Bound to specific address objects (${allTokens.join(", ")})`,
        geoObjectsList,
        allowedCountriesStr: allAllowedCountriesList.join(", "),
        geoBypassRisk: "High",
        riskAssessment: "Technical assessment: Foreign IP space authorized to establish SSL-VPN sessions to perimeter gateway listener.",
        additionalBullets: bullets
      });

      return makeFinding({
        id: "SEC-VPN-01",
        component: "SSL VPN Geo-Fencing",
        status: "WARN",
        category: "SecOps Operational",
        source: src,
        data: {
          vdom,
          highRiskCountries: highRiskCountryNames,
          additionalCountries: additionalForeignCountryNames,
          suspectHeuristics: heuristicSuspectNames,
          domesticEntities: domesticEntities.map((d) => d.token),
          staticIps: staticIpList,
          buckets: b,
          activePoliciesCount: activeSslPolicies.length,
        },
        findingText,
        actionText: `Review foreign country list against client authorized travel list. If unauthorized, notify client immediately (Checklist ID 13) and remove them from source-address to mitigate brute-force and SSL-VPN exploit exposure.`,
        remediationCli: remCli,
      });
    }

    // Case 7: Strictly Domestic Israel Baseline
    const domesticListStr = domesticEntities.length ? [...new Set(domesticEntities.map((d) => d.token))].join(", ") : "Israel";
    const bullets = [];
    if (staticIpList.length > 0) {
      bullets.push(`Configured Static IPs/Hosts: ${staticIpList.join(", ")}`);
    }
    bullets.push("Foreign Access: Zero foreign countries allowed (restricted strictly to domestic Israel baseline).");

    const findingText = buildSecVpn01ObservedState({
      configStatus: `Bound to specific address objects (${allTokens.join(", ")})`,
      geoObjectsList,
      allowedCountriesStr: domesticGeoList.length ? domesticGeoList.join(", ") : "Israel (IL)",
      geoBypassRisk: "None",
      riskAssessment: "Technical assessment: Perimeter gateway listener strictly restricted to authorized domestic Israel geolocation.",
      additionalBullets: bullets
    });

    return makeFinding({
      id: "SEC-VPN-01",
      component: "SSL VPN Geo-Fencing",
      status: "PASS",
      category: "SecOps Operational",
      source: src,
      data: {
        vdom,
        domesticEntities: domesticEntities.map((d) => d.token),
        domesticStr: domesticListStr,
        staticIps: staticIpList,
      },
      findingText,
      actionText: "",
      remediationCli: "",
    });
  }

  if (activeVdomData.length === 1) {
    return evaluateActiveVdom(activeVdomData[0]);
  }

  const results = activeVdomData.map((d) => evaluateActiveVdom(d));
  const fail = results.find((r) => r.status === "FAIL");
  if (fail) return fail;
  const warn = results.find((r) => r.status === "WARN");
  if (warn) return warn;
  return results[0];
}

// =====================================================================
// CIS BENCHMARK & HARDENING RULES ENGINE (v3.0)
// Ported from 'forticheck' & 'fortios_hardening_validator'
// =====================================================================

/**
 * CIS-ADM-01: Admin Idle Timeout
 * Section: system global -> admintimeout
 * Rule: CIS requires <= 10 minutes. Factory default is 5 minutes.
 * Flag WARN only if > 10 min. If unset in .conf, return PASS with factory default observation.
 */
function checkCisAdmIdleTimeout(tokenizer, text) {
  let valStr = tokenizer ? (tokenizer.getSystemGlobalProperty("admintimeout") || tokenizer.getProperty("system global", "admintimeout")) : null;
  if (!valStr) {
    const m = /(?:set\s+)?admintimeout\s*[:=\s]\s*([0-9]+)/i.exec(text);
    if (m) valStr = m[1];
  }

  const hasGlobal = tokenizer ? (!!tokenizer.getSystemSection("system global") || !!tokenizer.getSection("system global")) : /config system global/i.test(text);
  const src = (tokenizer && (tokenizer.getSystemSection("system global") || tokenizer.getSection("system global"))) ? "conf" : "cli";

  if (!valStr && !hasGlobal) {
    return makeFinding({
      id: "CIS-ADM-01",
      component: "Admin Idle Timeout",
      status: "NOT_EVALUATED",
      category: "CIS Benchmark",
      source: src,
      data: { timeout: null },
      findingText: "Control not evaluated: Section 'config system global' is missing from configuration.",
      actionText: "Include 'config system global' in configuration export to evaluate administrator idle timeout.",
    });
  }

  const val = valStr ? parseInt(valStr, 10) : null;
  const remCli = "config system global\n    set admintimeout 10\nend";

  if (val !== null && !isNaN(val)) {
    if (val > 10) {
      return makeFinding({
        id: "CIS-ADM-01",
        component: "Admin Idle Timeout",
        status: "WARN",
        category: "CIS Benchmark",
        source: src,
        data: { timeout: val },
        findingText: `Administrator idle timeout is ${val} minutes (> 10 min). CIS benchmark requires <= 10 minutes to mitigate unauthorized console/GUI session hijacking.`,
        actionText: "Configure administrator idle timeout to 10 minutes or less.",
        remediationCli: remCli,
      });
    }
    return makeFinding({
      id: "CIS-ADM-01",
      component: "Admin Idle Timeout",
      status: "PASS",
      category: "CIS Benchmark",
      source: src,
      data: { timeout: val },
      findingText: `Administrator idle timeout is compliant: ${val} minutes (<= 10 min CIS threshold).`,
      actionText: "",
      remediationCli: "",
    });
  }

  // val === null (unset in .conf delta)
  return makeFinding({
    id: "CIS-ADM-01",
    component: "Admin Idle Timeout",
    status: "PASS",
    category: "CIS Benchmark",
    source: src,
    data: { timeout: 5 },
    findingText: "Administrator idle timeout is unset in static backup. FortiOS factory default (5 minutes) is active and complies with CIS benchmark (<= 10 minutes). Explicitly configuring 'set admintimeout 10' is recommended to preserve configuration persistence.",
    actionText: "",
    remediationCli: "",
  });
}

/**
 * CIS-ADM-02: Admin Account Lockout
 * Section: system global -> admin-lockout-threshold & admin-lockout-duration
 * Rule: Factory default threshold is 3 (compliant), duration is 60s (CIS requires >= 300s).
 * Flag WARN if lockout parameters are unset, disabled (threshold: 0), or duration < 300s.
 */
function checkCisAdmAccountLockout(tokenizer, text) {
  let threshStr = tokenizer ? (tokenizer.getSystemGlobalProperty("admin-lockout-threshold") || tokenizer.getProperty("system global", "admin-lockout-threshold")) : null;
  let durStr = tokenizer ? (tokenizer.getSystemGlobalProperty("admin-lockout-duration") || tokenizer.getProperty("system global", "admin-lockout-duration")) : null;

  if (!threshStr) {
    const mThresh = /(?:set\s+)?admin-lockout-threshold\s*[:=\s]\s*([0-9]+)/i.exec(text);
    if (mThresh) threshStr = mThresh[1];
  }
  if (!durStr) {
    const mDur = /(?:set\s+)?admin-lockout-duration\s*[:=\s]\s*([0-9]+)/i.exec(text);
    if (mDur) durStr = mDur[1];
  }

  const hasGlobal = tokenizer ? (!!tokenizer.getSystemSection("system global") || !!tokenizer.getSection("system global")) : /config system global/i.test(text);
  const src = (tokenizer && (tokenizer.getSystemSection("system global") || tokenizer.getSection("system global"))) ? "conf" : "cli";
  const remCli = "config system global\n    set admin-lockout-threshold 3\n    set admin-lockout-duration 300\nend";

  if (!threshStr && !durStr && !hasGlobal) {
    return makeFinding({
      id: "CIS-ADM-02",
      component: "Admin Account Lockout",
      status: "NOT_EVALUATED",
      category: "CIS Benchmark",
      source: src,
      data: {},
      findingText: "Control not evaluated: Section 'config system global' is missing from configuration.",
      actionText: "Include 'config system global' in configuration export to evaluate administrator account lockout.",
      remediationCli: remCli,
    });
  }

  // Case 1: Both parameters unset in static backup (.conf delta)
  if (threshStr === null && durStr === null) {
    return makeFinding({
      id: "CIS-ADM-02",
      component: "Admin Account Lockout",
      status: "WARN",
      category: "CIS Benchmark",
      source: src,
      data: { threshold: 3, duration: 60 },
      findingText: "Lockout parameters unset in static backup. FortiOS factory default threshold (3 attempts) is active, but lockout duration (60s) is below the CIS recommended duration (>= 300s).",
      actionText: "Configure administrator lockout threshold (<= 3 attempts) and extend lockout duration to >= 300 seconds.",
      remediationCli: remCli,
    });
  }

  const threshold = threshStr ? parseInt(threshStr, 10) : 3;
  const duration = durStr ? parseInt(durStr, 10) : 60;

  if (threshStr !== null && threshold <= 0) {
    return makeFinding({
      id: "CIS-ADM-02",
      component: "Admin Account Lockout",
      status: "WARN",
      category: "CIS Benchmark",
      source: src,
      data: { threshold, duration },
      findingText: "Administrator account lockout threshold is disabled or unset (threshold: 0 / missing). Brute-force authentication protection is inactive.",
      actionText: "Enable administrator lockout threshold (<= 3 attempts) and lockout duration (>= 300 seconds) to mitigate brute-force attacks.",
      remediationCli: remCli,
    });
  }

  if (threshold > 3 || duration < 300) {
    return makeFinding({
      id: "CIS-ADM-02",
      component: "Admin Account Lockout",
      status: "WARN",
      category: "CIS Benchmark",
      source: src,
      data: { threshold, duration },
      findingText: `Administrator account lockout parameters are suboptimal (threshold: ${threshold} attempts, duration: ${duration}s). CIS benchmark requires threshold <= 3 attempts and duration >= 300 seconds.`,
      actionText: "Configure administrator lockout threshold (<= 3 attempts) and extend lockout duration to >= 300 seconds.",
      remediationCli: remCli,
    });
  }

  return makeFinding({
    id: "CIS-ADM-02",
    component: "Admin Account Lockout",
    status: "PASS",
    category: "CIS Benchmark",
    source: src,
    data: { threshold, duration },
    findingText: `Administrator account lockout is enforced: threshold ${threshold} failed attempt(s), lockout duration ${duration} seconds.`,
    actionText: "",
    remediationCli: "",
  });
}

/**
 * CIS-ADM-03: Non-Standard Administrative Ports
 * Section: system global -> admin-port & admin-sport
 * Rule: Flag WARN if default HTTP (80) or default HTTPS (443) is used.
 */
function checkCisAdmAdminPorts(tokenizer, text) {
  let portStr = tokenizer ? (tokenizer.getSystemGlobalProperty("admin-port") || tokenizer.getProperty("system global", "admin-port")) : null;
  let sportStr = tokenizer ? (tokenizer.getSystemGlobalProperty("admin-sport") || tokenizer.getProperty("system global", "admin-sport")) : null;

  if (!portStr) {
    const mPort = /(?:set\s+)?admin-port\s*[:=\s]\s*([0-9]+)/i.exec(text);
    if (mPort) portStr = mPort[1];
  }
  if (!sportStr) {
    const mSport = /(?:set\s+)?admin-sport\s*[:=\s]\s*([0-9]+)/i.exec(text);
    if (mSport) sportStr = mSport[1];
  }

  const hasGlobal = tokenizer ? (!!tokenizer.getSystemSection("system global") || !!tokenizer.getSection("system global")) : /config system global/i.test(text);
  const src = (tokenizer && (tokenizer.getSystemSection("system global") || tokenizer.getSection("system global"))) ? "conf" : "cli";

  if (!hasGlobal && !portStr && !sportStr) {
    return makeFinding({
      id: "CIS-ADM-03",
      component: "Non-Standard Admin Ports",
      status: "NOT_EVALUATED",
      category: "CIS Benchmark",
      source: src,
      data: { port: null, sport: null },
      findingText: "Control not evaluated: Section 'config system global' is missing from configuration.",
      actionText: "Include 'config system global' in configuration export to evaluate administrative ports.",
    });
  }

  const port = portStr ? parseInt(portStr, 10) : 80;
  const sport = sportStr ? parseInt(sportStr, 10) : 443;
  const remCli = "config system global\n    set admin-port 8080\n    set admin-sport 8443\nend";

  if (port === 80 || sport === 443) {
    return makeFinding({
      id: "CIS-ADM-03",
      component: "Non-Standard Admin Ports",
      status: "WARN",
      category: "CIS Benchmark",
      source: src,
      data: { port, sport },
      findingText: `Default administrative port(s) in use (HTTP: ${port}, HTTPS: ${sport}). Standard ports 80/443 increase exposure to automated reconnaissance and unauthorized probing.`,
      actionText: "Change default administration ports (HTTP 80 / HTTPS 443) to custom non-standard ports (e.g. 8080 / 8443).",
      remediationCli: remCli,
    });
  }

  return makeFinding({
    id: "CIS-ADM-03",
    component: "Non-Standard Admin Ports",
    status: "PASS",
    category: "CIS Benchmark",
    source: src,
    data: { port, sport },
    findingText: `Non-standard administrative ports configured (HTTP: ${port}, HTTPS: ${sport}).`,
    actionText: "",
    remediationCli: "",
  });
}

/**
 * CIS-SYS-01: System Hostname Hardening
 * Section: system global -> hostname
 * Rule: Flag WARN if hostname is default "FortiGate" or blank.
 */
function checkCisSysHostname(tokenizer, text) {
  let hostname = tokenizer ? cleanVal(tokenizer.getSystemGlobalProperty("hostname") || tokenizer.getProperty("system global", "hostname")) : null;
  if (!hostname && text) {
    const m = /(?:set\s+)?hostname\s*(?::\s*|\s+)"?([^"\r\n\s]+)/i.exec(text);
    if (m) hostname = m[1];
  }

  const hasGlobal = tokenizer ? (!!tokenizer.getSystemSection("system global") || !!tokenizer.getSection("system global")) : /config system global/i.test(text);
  const src = (tokenizer && (tokenizer.getSystemSection("system global") || tokenizer.getSection("system global"))) ? "conf" : "cli";

  if (!hostname && !hasGlobal) {
    return makeFinding({
      id: "CIS-SYS-01",
      component: "Hostname Hardening",
      status: "NOT_EVALUATED",
      category: "CIS Benchmark",
      source: src,
      data: { hostname: null },
      findingText: "Control not evaluated: Section 'config system global' is missing from configuration.",
      actionText: "Include 'config system global' in configuration export to evaluate system hostname.",
    });
  }

  const isDefault = !hostname || /^(FortiGate|FortiGate-\w+)$/i.test(hostname);
  const remCli = "config system global\n    set hostname <Company>-FW-Primary\nend";

  if (isDefault) {
    return makeFinding({
      id: "CIS-SYS-01",
      component: "Hostname Hardening",
      status: "WARN",
      category: "CIS Benchmark",
      source: src,
      data: { hostname },
      findingText: `Default or unconfigured system hostname detected: "${hostname || 'FortiGate'}". Asset identification and security monitoring require unique hostnames.`,
      actionText: "Assign a unique and descriptive hostname to adhere to enterprise asset naming standards and prevent administrative confusion.",
      remediationCli: remCli,
    });
  }

  return makeFinding({
    id: "CIS-SYS-01",
    component: "Hostname Hardening",
    status: "PASS",
    category: "CIS Benchmark",
    source: src,
    data: { hostname },
    findingText: `Custom descriptive hostname configured: "${hostname}".`,
    actionText: "",
    remediationCli: "",
  });
}

/**
 * CIS-SYS-02: NTP & Timezone Audit
 * Section: system ntp and system global -> timezone
 * Rule: Verify active NTP synchronization (set ntpsync enable) and defined timezone.
 */
function checkCisSysNtpTimezone(tokenizer, text = "") {
  let ntpSync = tokenizer ? cleanVal(tokenizer.getSystemProperty("system ntp", "ntpsync") || tokenizer.getProperty("system ntp", "ntpsync")) : null;
  let timezone = tokenizer ? cleanVal(tokenizer.getSystemGlobalProperty("timezone") || tokenizer.getProperty("system global", "timezone")) : null;

  if (!ntpSync && text) {
    const m = /set\s+ntpsync\s+(\S+)/i.exec(text);
    if (m) ntpSync = m[1];
  }
  if (!timezone && text) {
    const m = /set\s+timezone\s+(\S+)/i.exec(text);
    if (m) timezone = m[1];
  }

  const hasNtpBlock = tokenizer ? (!!tokenizer.getSystemSection("system ntp") || !!tokenizer.getSection("system ntp")) : /config\s+system\s+ntp/i.test(text);
  const hasGlobal = tokenizer ? (!!tokenizer.getSystemSection("system global") || !!tokenizer.getSection("system global")) : /config\s+system\s+global/i.test(text);
  const hasLiveNtp = /get\s+system\s+ntp/i.test(text);
  const src = tokenizer ? "conf" : "cli";
  const remCli = "config system ntp\n    set ntpsync enable\n    set type fortiguard\nend";

  if (!hasNtpBlock && !hasGlobal && !hasLiveNtp) {
    return makeFinding({
      id: "CIS-SYS-02",
      component: "NTP & Timezone Audit",
      status: "NOT_EVALUATED",
      category: "CIS Benchmark",
      source: src,
      data: {},
      findingText: "Control not evaluated: Sections 'config system ntp' and 'config system global' are missing from configuration backup.",
      actionText: "Ensure NTP synchronization and timezone configuration are audited via live CLI or full configuration backup.",
      remediationCli: remCli,
    });
  }

  const isExplicitlyDisabled = ntpSync && ntpSync.toLowerCase() === "disable";
  const isCliSyncFailed = !tokenizer && (
    /synchronized:\s*no/i.test(text) ||
    /ntpsync\s+is\s+disabled/i.test(text) ||
    /synchronization\s+failed/i.test(text)
  );

  if (isExplicitlyDisabled || isCliSyncFailed) {
    return makeFinding({
      id: "CIS-SYS-02",
      component: "NTP & Timezone Audit",
      status: "WARN",
      category: "CIS Benchmark",
      source: src,
      data: { ntpSync: ntpSync || "disabled", timezone },
      findingText: `NTP time synchronization is disabled or unverified (ntpsync: ${ntpSync || 'disabled'}). Inaccurate timestamps impair forensic log correlation and incident response.`,
      actionText: "Enable network time synchronization (NTP) with verified time sources and configure accurate local timezone for forensic log correlation.",
      remediationCli: remCli,
    });
  }

  if (tokenizer && !hasNtpBlock) {
    return makeFinding({
      id: "CIS-SYS-02",
      component: "NTP & Timezone Audit",
      status: "PASS",
      category: "CIS Benchmark",
      source: src,
      data: { ntpSync: "enable", timezone: timezone || "default", isFactoryDefault: true },
      findingText: "NTP configuration block is omitted from static backup. Appliance relies on FortiOS factory default (FortiGuard NTP synchronization enabled).",
      actionText: "",
      remediationCli: "",
    });
  }

  return makeFinding({
    id: "CIS-SYS-02",
    component: "NTP & Timezone Audit",
    status: "PASS",
    category: "CIS Benchmark",
    source: src,
    data: { ntpSync: ntpSync || "enable", timezone },
    findingText: `NTP time synchronization is enabled with configured system timezone (${timezone || 'configured'}).`,
    actionText: "",
    remediationCli: "",
  });
}

/**
 * CIS-AUTH-01: Global Password Policy
 * Section: system password-policy
 * Rule: Require status enable, min-length >= 12, and character complexity for all 4 categories:
 * min-lower-case-letter, min-upper-case-letter, min-non-alphanumeric, min-number (all >= 1).
 * If section missing in static backup, flag WARN (non-compliant FortiOS default).
 */
function checkCisAuthPasswordPolicy(tokenizer, text = "") {
  let status = tokenizer ? (cleanVal(tokenizer.getSystemProperty("system password-policy", "status")) || cleanVal(tokenizer.getSystemProperty("system password-policy", "status-global")) || cleanVal(tokenizer.getProperty("system password-policy", "status")) || cleanVal(tokenizer.getProperty("system password-policy", "status-global"))) : null;
  let minLengthStr = tokenizer ? (cleanVal(tokenizer.getSystemProperty("system password-policy", "minimum-length")) || cleanVal(tokenizer.getSystemProperty("system password-policy", "min-length")) || cleanVal(tokenizer.getProperty("system password-policy", "minimum-length")) || cleanVal(tokenizer.getProperty("system password-policy", "min-length"))) : null;
  let minLowerStr = tokenizer ? (cleanVal(tokenizer.getSystemProperty("system password-policy", "min-lower-case-letter")) || cleanVal(tokenizer.getProperty("system password-policy", "min-lower-case-letter"))) : null;
  let minUpperStr = tokenizer ? (cleanVal(tokenizer.getSystemProperty("system password-policy", "min-upper-case-letter")) || cleanVal(tokenizer.getProperty("system password-policy", "min-upper-case-letter"))) : null;
  let minNonAlphaStr = tokenizer ? (cleanVal(tokenizer.getSystemProperty("system password-policy", "min-non-alphanumeric")) || cleanVal(tokenizer.getProperty("system password-policy", "min-non-alphanumeric"))) : null;
  let minNumStr = tokenizer ? (cleanVal(tokenizer.getSystemProperty("system password-policy", "min-number")) || cleanVal(tokenizer.getProperty("system password-policy", "min-number"))) : null;

  if (!status && text) {
    const m = /config\s+system\s+password-policy[\s\S]*?set\s+(?:status|status-global)\s+(\S+)/i.exec(text);
    if (m) status = m[1];
  }
  if (!minLengthStr && text) {
    const m = /config\s+system\s+password-policy[\s\S]*?set\s+(?:minimum-length|min-length)\s+([0-9]+)/i.exec(text);
    if (m) minLengthStr = m[1];
  }
  if (!minLowerStr && text) {
    const m = /config\s+system\s+password-policy[\s\S]*?set\s+min-lower-case-letter\s+([0-9]+)/i.exec(text);
    if (m) minLowerStr = m[1];
  }
  if (!minUpperStr && text) {
    const m = /config\s+system\s+password-policy[\s\S]*?set\s+min-upper-case-letter\s+([0-9]+)/i.exec(text);
    if (m) minUpperStr = m[1];
  }
  if (!minNonAlphaStr && text) {
    const m = /config\s+system\s+password-policy[\s\S]*?set\s+min-non-alphanumeric\s+([0-9]+)/i.exec(text);
    if (m) minNonAlphaStr = m[1];
  }
  if (!minNumStr && text) {
    const m = /config\s+system\s+password-policy[\s\S]*?set\s+min-number\s+([0-9]+)/i.exec(text);
    if (m) minNumStr = m[1];
  }

  const hasPwdPolicy = tokenizer ? (!!tokenizer.getSystemSection("system password-policy") || !!tokenizer.getSection("system password-policy")) : /config\s+system\s+password-policy/i.test(text);
  const src = tokenizer ? "conf" : "cli";
  const remCli = "config system password-policy\n    set status enable\n    set minimum-length 12\n    set min-lower-case-letter 1\n    set min-upper-case-letter 1\n    set min-non-alphanumeric 1\n    set min-number 1\nend";

  // If section is missing in configuration or CLI input, return NOT_EVALUATED
  if (!hasPwdPolicy && !status && !minLengthStr) {
    return makeFinding({
      id: "CIS-AUTH-01",
      component: "Global Password Policy",
      status: "NOT_EVALUATED",
      category: "CIS Benchmark",
      source: src,
      data: {},
      findingText: "Control not evaluated: Section 'config system password-policy' is missing from configuration.",
      actionText: "Include 'config system password-policy' in configuration export to evaluate administrator password policy.",
      remediationCli: remCli,
    });
  }

  const minLength = minLengthStr ? parseInt(minLengthStr, 10) : 0;
  const minLower = minLowerStr ? parseInt(minLowerStr, 10) : 0;
  const minUpper = minUpperStr ? parseInt(minUpperStr, 10) : 0;
  const minNonAlpha = minNonAlphaStr ? parseInt(minNonAlphaStr, 10) : 0;
  const minNum = minNumStr ? parseInt(minNumStr, 10) : 0;

  const isEnabled = status && status.toLowerCase() === "enable";

  const missingComplexity = [];
  if (minLower < 1) missingComplexity.push("lowercase letters");
  if (minUpper < 1) missingComplexity.push("uppercase letters");
  if (minNonAlpha < 1) missingComplexity.push("special characters");
  if (minNum < 1) missingComplexity.push("numbers");

  if (!isEnabled || minLength < 12 || missingComplexity.length > 0) {
    const reasons = [];
    if (!isEnabled) reasons.push("policy status is disabled");
    if (minLength < 12) reasons.push(`minimum length is ${minLength || 0} (<12)`);
    if (missingComplexity.length > 0) reasons.push(`missing complexity enforcement for: ${missingComplexity.join(", ")}`);

    return makeFinding({
      id: "CIS-AUTH-01",
      component: "Global Password Policy",
      status: "WARN",
      category: "CIS Benchmark",
      source: src,
      data: { status: status || "disable", minLength, missingComplexity },
      findingText: `Global administrator password policy is non-compliant (${reasons.join("; ")}). CIS benchmark requires status enabled, minimum length >= 12 characters, and all 4 complexity categories enabled.`,
      actionText: "Enforce global administrator password policy with minimum length >= 12 characters and character complexity requirements.",
      remediationCli: remCli,
    });
  }

  return makeFinding({
    id: "CIS-AUTH-01",
    component: "Global Password Policy",
    status: "PASS",
    category: "CIS Benchmark",
    source: src,
    data: { status: "enable", minLength, minLower, minUpper, minNonAlpha, minNum },
    findingText: `Global password policy enforced: minimum length ${minLength} characters with all 4 complexity categories required (lowercase, uppercase, numbers, non-alphanumeric).`,
    actionText: "",
    remediationCli: "",
  });
}

/**
 * CIS-MGMT-01: Insecure SNMP Community Strings
 * Section: system snmp community
 * Rule: Flag FAIL if default strings "public" or "private" are found. Recommend SNMPv3.
 */
function checkCisMgmtSnmpCommunity(tokenizer, text = "") {
  const commList = [];
  const src = tokenizer ? "conf" : "cli";

  // 1. Strictly isolate the block (?:config|show)\s+system\s+snmp\s+community([\s\S]*?)(?:^end|\n\s*end)
  let blockText = "";
  if (tokenizer && (tokenizer.getSystemSection("system snmp community") || tokenizer.getSection("system snmp community"))) {
    const entries = tokenizer.getEntries("system snmp community");
    for (const [id, entry] of Object.entries(entries)) {
      const origId = entry.name || entry._origKey || id;
      const name = cleanVal(entry.properties["name"] || "");
      const status = cleanVal(entry.properties["status"] || "enable").toLowerCase();
      const hosts = cleanVal(entry.properties["hosts"] || entry.properties["hosts6"] || "");
      if (name) {
        commList.push({ id: origId, name, status, hosts: hosts || "Unrestricted (0.0.0.0/0)" });
      }
    }
  } else if (text) {
    const snmpMatch = /(?:config|show)\s+system\s+snmp\s+community([\s\S]*?)(?:^end|\n\s*end)/im.exec(text);
    if (snmpMatch) {
      blockText = snmpMatch[1];
      const editRe = /edit\s+(?:"([^"]+)"|(\d+|\S+))([\s\S]*?)next/gi;
      let m;
      while ((m = editRe.exec(blockText)) !== null) {
        const id = m[1] || m[2];
        const body = m[3];
        const nameMatch = /set\s+name\s+(?:"([^"]+)"|(\S+))/i.exec(body);
        const statusMatch = /set\s+status\s+(\S+)/i.exec(body);
        const hostsMatch = /set\s+(?:hosts|hosts6)\s+([^\n]+)/i.exec(body);
        const hostIpMatch = /set\s+ip\s+([^\n]+)/i.exec(body);
        const name = nameMatch ? (nameMatch[1] || nameMatch[2]) : "";
        const status = statusMatch ? statusMatch[1].toLowerCase() : "enable";
        const hosts = hostsMatch ? hostsMatch[1].trim() : (hostIpMatch ? hostIpMatch[1].trim() : "");
        if (name) {
          commList.push({ id, name, status, hosts: hosts || "Unrestricted (0.0.0.0/0)" });
        }
      }
    }
  }

  const hasSnmpSection = tokenizer
    ? (!!tokenizer.getSystemSection("system snmp community") || !!tokenizer.getSection("system snmp community"))
    : /(?:config|show)\s+system\s+snmp\s+community/i.test(text);

  if (!commList.length && !hasSnmpSection) {
    return makeFinding({
      id: "CIS-MGMT-01",
      component: "SNMP Community Strings",
      status: "NOT_EVALUATED",
      category: "CIS Benchmark",
      source: src,
      data: { communities: [], count: 0 },
      findingText: "Control not evaluated: Section 'config system snmp community' is missing from configuration.",
      actionText: "Audit SNMP community strings via live CLI or full configuration backup.",
      remediationCli: "",
    });
  }

  // 2. If the section exists but contains no active communities, return PASS
  if (!commList.length) {
    return makeFinding({
      id: "CIS-MGMT-01",
      component: "SNMP Community Strings",
      status: "PASS",
      category: "CIS Benchmark",
      source: src,
      data: { communities: [], count: 0 },
      findingText: "No legacy SNMPv1/v2c communities configured on the appliance. Device is protected against unencrypted SNMP polling and credential interception.",
      actionText: "",
      remediationCli: "",
    });
  }

  const activeCommunities = commList.filter((c) => c.status !== "disable");
  if (!activeCommunities.length) {
    return makeFinding({
      id: "CIS-MGMT-01",
      component: "SNMP Community Strings",
      status: "PASS",
      category: "CIS Benchmark",
      source: src,
      data: { communities: commList, activeCount: 0 },
      findingText: "All legacy SNMPv1/v2c communities are disabled (set status disable). Device is protected against unencrypted SNMP polling.",
      actionText: "",
      remediationCli: "",
    });
  }

  // 3. Flag FAIL if name is "public" or "private"
  const defaultCommunities = activeCommunities.filter(
    (c) => c.name.toLowerCase() === "public" || c.name.toLowerCase() === "private"
  );

  if (defaultCommunities.length > 0) {
    const ids = defaultCommunities.map((c) => `    delete ${c.id}`).join("\n");
    const bulletLines = defaultCommunities.map(
      (c) => `  • Community: "${c.name}" (ID ${c.id}) | Permitted Hosts: ${c.hosts} | Status: Active (Enabled)`
    );
    const lines = [
      "Insecure default SNMP community string(s) detected:",
      ...bulletLines,
      "",
      "Impact: Default community strings ('public', 'private') allow unauthorized reconnaissance, device enumeration, and MIB disclosure via unencrypted SNMPv1/v2c."
    ];
    return makeFinding({
      id: "CIS-MGMT-01",
      component: "SNMP Community Strings",
      status: "FAIL",
      category: "CIS Benchmark",
      source: src,
      data: { communities: commList, activeCount: activeCommunities.length, defaultCount: defaultCommunities.length },
      findingText: lines.join("\n"),
      actionText: "Delete default SNMP community strings ('public', 'private') immediately and migrate all network monitoring to SNMPv3 with SHA/AES encryption.",
      remediationCli: `config system snmp community\n${ids}\nend`,
    });
  }

  // 4. Flag WARN if custom SNMPv1/v2c strings are configured
  const bulletLines = activeCommunities.map(
    (c) => `  • Community: "${c.name}" (ID ${c.id}) | Permitted Hosts: ${c.hosts} | Status: Active (Enabled)`
  );
  const lines = [
    "Legacy SNMPv1/v2c community string(s) configured:",
    ...bulletLines,
    "",
    "Impact: SNMPv1/v2c transmits community strings and system metrics in plaintext without encryption, exposing monitoring traffic to packet sniffing."
  ];

  return makeFinding({
    id: "CIS-MGMT-01",
    component: "SNMP Community Strings",
    status: "WARN",
    category: "CIS Benchmark",
    source: src,
    data: { communities: commList, activeCount: activeCommunities.length, defaultCount: 0 },
    findingText: lines.join("\n"),
    actionText: "Migrate legacy SNMPv1/v2c communities to SNMPv3 with dedicated user authentication (SHA-256) and privacy encryption (AES-256).",
    remediationCli: "config system snmp user\n    edit \"snmp3user\"\n        set security-level auth-priv\n        set auth-proto sha256\n        set auth-pwd <password>\n        set priv-proto aes256\n        set priv-pwd <password>\n    next\nend",
  });
}

/**
 * SEC-FW-01: Overly Permissive Any-to-Any Firewall Rules
 * Section: firewall policy
 * Rule: Scan all policies with set action accept. Flag WARN if srcaddr is "all" AND dstaddr is "all"
 * AND service is "ALL" without UTM security profiles applied.
 */
function checkSecFirewallAnyPolicy(tokenizer, text = "") {
  const policyList = getFirewallPolicyList(tokenizer, text);
  const hasFwPolicy = tokenizer ? !!tokenizer.getSection("firewall policy") : /config\s+firewall\s+policy/i.test(text);
  const src = tokenizer ? "conf" : "cli";

  if (!hasFwPolicy && !policyList.length) {
    return makeFinding({
      id: "SEC-FW-01",
      component: "Any-to-Any Firewall Rules",
      status: "NOT_EVALUATED",
      category: "Firewall Policy & Access Control",
      source: src,
      data: {},
      findingText: "Control not evaluated: Section 'config firewall policy' is missing from configuration backup.",
      actionText: "Ensure firewall policies are included in the configuration backup to evaluate Any-to-Any exposure.",
      remediationCli: "",
    });
  }

  const offending = [];

  for (const pol of policyList) {
    if (pol.status === "disable") continue;
    if (pol.action === "accept") {
      const isSrcAll = pol.srcaddr.some((a) => a.toLowerCase() === "all");
      const isDstAll = pol.dstaddr.some((a) => a.toLowerCase() === "all");
      const isSrvAll = pol.service.some((s) => s.toLowerCase() === "all");
      const hasUtm = pol.utmStatus === "enable";

      if (isSrcAll && isDstAll && isSrvAll && !hasUtm) {
        offending.push(pol);
      }
    }
  }

  if (offending.length > 0) {
    const first = offending[0];
    const bulletList = offending
      .map((p) => `  • Policy ID ${p.id}${p.name ? ` ("${p.name}")` : ""}: src: [${p.srcaddr.join(", ")}], dst: [${p.dstaddr.join(", ")}], service: [${p.service.join(", ")}]`)
      .join("\n");
    return makeFinding({
      id: "SEC-FW-01",
      component: "Any-to-Any Firewall Rules",
      status: "WARN",
      category: "Firewall Policy & Access Control",
      source: src,
      data: { offendingCount: offending.length, totalCount: policyList.length },
      findingText: `${offending.length} firewall policy/policies configured with overly permissive Any-to-Any access (src: all, dst: all, service: ALL) without active UTM security inspection:\n${bulletList}`,
      actionText: "Restrict source/destination address objects and service ports, or enable UTM inspection profiles (AV, IPS, Web Filter, Deep SSL Inspection).",
      remediationCli: `config firewall policy\n    edit ${first.id}\n        set utm-status enable\n        set ssl-ssh-profile "certificate-inspection"\n    next\nend`,
    });
  }

  return makeFinding({
    id: "SEC-FW-01",
    component: "Any-to-Any Firewall Rules",
    status: "PASS",
    category: "Firewall Policy & Access Control",
    source: src,
    data: { offendingCount: 0, totalCount: policyList.length },
    findingText: `All ${policyList.length} firewall policies enforce specific address/service scopes or active UTM inspection. No unrestricted any-to-any accept rules detected.`,
    actionText: "",
    remediationCli: "",
  });
}

/**
 * SEC-FW-02: Inbound Dangerous Ports from WAN
 * Section: config firewall policy
 * Scan firewall policies where srcintf is a WAN interface and action is accept.
 * Flag FAIL if destination ports/services include RDP (3389), SSH (22), Telnet (23), or SMB (445) directly from external sources (srcaddr "all").
 */
function checkSecInboundDangerousPorts(tokenizer, text = "") {
  const policyList = getFirewallPolicyList(tokenizer, text);
  const hasPolicySection = tokenizer ? !!tokenizer.getSection("firewall policy") : /(?:config|show)\s+firewall\s+policy/i.test(text);
  const src = tokenizer ? "conf" : "cli";

  if (!policyList.length && !hasPolicySection) {
    return makeFinding({
      id: "SEC-FW-02",
      component: "Inbound Dangerous Ports from WAN",
      status: "NOT_EVALUATED",
      category: "Firewall Policy & Access Control",
      source: src,
      data: {},
      findingText: "Control not evaluated: Section 'config firewall policy' is missing from configuration backup.",
      actionText: "Ensure firewall policies are included in the configuration backup to audit inbound external ports.",
      remediationCli: "",
    });
  }
  if (!policyList.length) return null;

  const wanSet = getKnownWanInterfaces(tokenizer, text);
  const offendingPolicies = [];

  for (const p of policyList) {
    if (p.status === "disable") continue;
    if (p.action !== "accept") continue;

    const wanIngress = p.srcintf.filter((intf) => isWanInterface(intf, wanSet));
    if (!wanIngress.length) continue;

    const isSrcAll = p.srcaddr.some((addr) => addr.toLowerCase() === "all");
    if (!isSrcAll) continue;

    const detected = [];
    for (const s of p.service) {
      const lower = s.toLowerCase();
      if (/\b(?:rdp|ms-wbt-server|3389)\b/i.test(lower)) {
        detected.push("RDP (3389)");
      } else if (/\b(?:ssh|22)\b/i.test(lower)) {
        detected.push("SSH (22)");
      } else if (/\b(?:telnet|23)\b/i.test(lower)) {
        detected.push("Telnet (23)");
      } else if (/\b(?:smb|samba|microsoft-ds|netbios-ssn|445|139)\b/i.test(lower)) {
        detected.push("SMB (445)");
      }
    }

    if (detected.length > 0) {
      offendingPolicies.push({
        id: p.id,
        name: p.name,
        srcintf: wanIngress,
        dstaddr: p.dstaddr.join(", "),
        services: [...new Set(detected)],
      });
    }
  }

  if (offendingPolicies.length > 0) {
    const first = offendingPolicies[0];
    const bulletList = offendingPolicies
      .map((p) => `  • Policy ID ${p.id}${p.name ? ` ("${p.name}")` : ""}: Ingress = ${p.srcintf.join(", ")}, Services = [${p.services.join(", ")}], Destination = ${p.dstaddr}`)
      .join("\n");

    return makeFinding({
      id: "SEC-FW-02",
      component: "Inbound Dangerous Ports from WAN",
      status: "FAIL",
      category: "Firewall Policy & Access Control",
      source: src,
      data: { offendingCount: offendingPolicies.length },
      findingText: `Critical external exposure: ${offendingPolicies.length} active firewall policy/policies permit dangerous management or file-sharing service(s) directly from the internet (srcaddr 'all'):\n${bulletList}`,
      actionText: `Immediately disable or restrict Policy ID ${first.id}. Inbound management services (RDP/SSH/Telnet) and SMB file-sharing must NEVER be exposed directly to the public internet. Enforce SSL-VPN or IPSec with MFA, or restrict source address to dedicated authorized management IPs.`,
      remediationCli: `config firewall policy\n    edit ${first.id}\n        set status disable\n    next\nend`,
    });
  }

  return makeFinding({
    id: "SEC-FW-02",
    component: "Inbound Dangerous Ports from WAN",
    status: "PASS",
    category: "Firewall Policy & Access Control",
    source: src,
    data: { offendingCount: 0 },
    findingText: "No active firewall policies permit dangerous administrative or file-sharing services (RDP, SSH, Telnet, SMB) directly from WAN interfaces with source 'all'.",
    actionText: "",
    remediationCli: "",
  });
}

/**
 * CIS-LOG-01: Centralized Logging Redundancy
 * Section: log fortianalyzer setting / log syslogd setting
 * Rule: Flag WARN if neither remote centralized logging target is enabled.
 * If section missing in static backup, emit non-compliant WARN default (FortiOS default: logging disabled).
 */
function checkCisLogCentralized(tokenizer, text = "") {
  let fazStatus = tokenizer ? cleanVal(tokenizer.getProperty("log fortianalyzer setting", "status")) : null;
  let syslogStatus = tokenizer ? cleanVal(tokenizer.getProperty("log syslogd setting", "status")) : null;

  if (!fazStatus && text) {
    const m = /config\s+log\s+fortianalyzer\s+setting[\s\S]*?set\s+status\s+(\S+)/i.exec(text);
    if (m) fazStatus = m[1];
  }
  if (!syslogStatus && text) {
    const m = /config\s+log\s+syslogd\s+setting[\s\S]*?set\s+status\s+(\S+)/i.exec(text);
    if (m) syslogStatus = m[1];
  }

  const hasLogSection = tokenizer
    ? (!!tokenizer.getSection("log fortianalyzer setting") || !!tokenizer.getSection("log syslogd setting"))
    : /(?:log\s+fortianalyzer\s+setting|log\s+syslogd\s+setting)/i.test(text);

  const remCli = "config log fortianalyzer setting\n    set status enable\n    set server <ip-address>\nend";
  const src = tokenizer ? "conf" : "cli";

  // If remote logging sections are missing from configuration backup or CLI input, return NOT_EVALUATED
  if (!hasLogSection && !fazStatus && !syslogStatus) {
    return makeFinding({
      id: "CIS-LOG-01",
      component: "Centralized Logging Redundancy",
      status: "NOT_EVALUATED",
      category: "CIS Benchmark",
      source: src,
      data: { fazActive: false, syslogActive: false },
      findingText: "Control not evaluated: Remote logging sections ('log fortianalyzer setting', 'log syslogd setting') are missing from configuration.",
      actionText: "Configure centralized remote logging to FortiAnalyzer or Syslog to ensure log retention, non-repudiation, and continuous SIEM ingestion.",
      remediationCli: remCli,
    });
  }

  const fazActive = fazStatus && fazStatus.toLowerCase() === "enable";
  const syslogActive = syslogStatus && syslogStatus.toLowerCase() === "enable";

  if (!fazActive && !syslogActive) {
    return makeFinding({
      id: "CIS-LOG-01",
      component: "Centralized Logging Redundancy",
      status: "WARN",
      category: "CIS Benchmark",
      source: src,
      data: { fazActive: false, syslogActive: false },
      findingText: "No remote centralized logging target is enabled (FortiAnalyzer: disabled/unset, Syslog: disabled/unset). Local-only logging risks log loss during appliance failure or unauthorized tampering.",
      actionText: "Configure centralized remote logging to FortiAnalyzer or Syslog to ensure log retention, non-repudiation, and continuous SIEM ingestion.",
      remediationCli: remCli,
    });
  }

  const targets = [];
  if (fazActive) targets.push("FortiAnalyzer");
  if (syslogActive) targets.push("Syslog");

  return makeFinding({
    id: "CIS-LOG-01",
    component: "Centralized Logging Redundancy",
    status: "PASS",
    category: "CIS Benchmark",
    source: src,
    data: { fazActive, syslogActive, targets },
    findingText: `Centralized remote logging is configured and active (${targets.join(", ")}).`,
    actionText: "",
    remediationCli: "",
  });
}

/**
 * CIS-AUTH-02: Administrator Trusted Hosts
 * Target Section: config system admin
 * Rule: Flag WARN if any active admin account lacks trusthost or has 0.0.0.0 0.0.0.0 / 0.0.0.0/0.
 * Specify exact unconstrained administrator usernames in finding text.
 * Flag PASS if all admin accounts enforce source IP restrictions.
 */
function checkCisAuthTrustedHosts(tokenizer, text = "") {
  const admins = [];
  const src = tokenizer ? "conf" : "cli";

  if (tokenizer && tokenizer.getSection("system admin")) {
    const adminEntries = tokenizer.getEntries("system admin");
    for (const [name, entry] of Object.entries(adminEntries)) {
      const origName = entry.name || entry._origKey || name;
      const props = entry.properties || {};
      const status = cleanVal(props["status"] || "enable").toLowerCase();
      const trusthosts = [];
      for (const [k, v] of Object.entries(props)) {
        if (k.toLowerCase().startsWith("trusthost")) {
          trusthosts.push(cleanVal(v));
        }
      }
      admins.push({ name: origName, status, trusthosts });
    }
  } else if (text) {
    const secMatch = /(?:config\s+system\s+admin|show\s+system\s+admin)([\s\S]*?)(?:^end|\n\s*end)/im.exec(text);
    if (secMatch) {
      const blockRe = /edit\s+(?:"([^"]+)"|(\S+))([\s\S]*?)next/gi;
      let m;
      while ((m = blockRe.exec(secMatch[1])) !== null) {
        const name = m[1] || m[2];
        const body = m[3];
        const statusMatch = /set\s+status\s+(\S+)/i.exec(body);
        const status = statusMatch ? statusMatch[1].toLowerCase() : "enable";
        const thMatches = [...body.matchAll(/set\s+trusthost\d*\s+([^\n]+)/gi)].map((th) => cleanVal(th[1]));
        admins.push({ name, status, trusthosts: thMatches });
      }
    }
  }

  const hasAdminSection = tokenizer ? !!tokenizer.getSection("system admin") : /(?:config|show)\s+system\s+admin/i.test(text);
  if (!admins.length && !hasAdminSection) {
    return makeFinding({
      id: "CIS-AUTH-02",
      component: "Administrator Trusted Hosts",
      status: "NOT_EVALUATED",
      category: "CIS Benchmark",
      source: src,
      data: {},
      findingText: "Control not evaluated: Section 'config system admin' is missing from configuration backup.",
      actionText: "Audit administrator trusted host restrictions via live CLI or full configuration backup.",
      remediationCli: "",
    });
  }
  if (!admins.length) return null;

  const unconstrainedAdmins = [];

  for (const admin of admins) {
    // If an administrator account has set status disable, it is NOT an active threat.
    if (admin.status === "disable") {
      continue;
    }

    if (!admin.trusthosts.length) {
      unconstrainedAdmins.push(admin);
      continue;
    }

    const hasRestrictedHost = admin.trusthosts.some((th) => {
      const lower = th.toLowerCase().trim();
      return (
        lower !== "0.0.0.0 0.0.0.0" &&
        lower !== "0.0.0.0/0" &&
        lower !== "0.0.0.0/0.0.0.0" &&
        lower !== ""
      );
    });

    if (!hasRestrictedHost) {
      unconstrainedAdmins.push(admin);
    }
  }

  if (unconstrainedAdmins.length > 0) {
    const first = unconstrainedAdmins[0].name;
    const lines = [];

    if (unconstrainedAdmins.length === 1) {
      const a = unconstrainedAdmins[0];
      lines.push(`Location: config system admin -> edit "${a.name}"`);
      lines.push("Status: Active (Enabled) | Configured Trusthosts: None (0.0.0.0/0)");
      lines.push("Risk: Administrator account permits authentication attempts from any IP address worldwide.");
    } else {
      lines.push("Unrestricted administrator access detected on active account(s):");
      for (const a of unconstrainedAdmins) {
        lines.push(`  • Location: config system admin -> edit "${a.name}"`);
        lines.push("    Status: Active (Enabled) | Configured Trusthosts: None (0.0.0.0/0)");
        lines.push("    Risk: Administrator account permits authentication attempts from any IP address worldwide.");
      }
    }

    return makeFinding({
      id: "CIS-AUTH-02",
      component: "Administrator Trusted Hosts",
      status: "WARN",
      category: "CIS Benchmark",
      source: src,
      data: { unconstrainedCount: unconstrainedAdmins.length, unconstrainedNames: unconstrainedAdmins.map(a => a.name) },
      findingText: lines.join("\n"),
      actionText: "Configure trusted host (trusthost) source IP/subnet restrictions on all administrator accounts to prevent unauthorized access attempts.",
      remediationCli: `config system admin\n    edit "${first}"\n        set trusthost1 <trusted-ip/mask>\n    next\nend`,
    });
  }

  return makeFinding({
    id: "CIS-AUTH-02",
    component: "Administrator Trusted Hosts",
    status: "PASS",
    category: "CIS Benchmark",
    source: src,
    data: { unconstrainedCount: 0 },
    findingText: "All active administrator accounts enforce source IP restrictions via trusted hosts (trusthost). Disabled accounts are safely de-provisioned.",
    actionText: "",
    remediationCli: "",
  });
}

/**
 * CIS-TLS-01: Strong Crypto & TLS Protocol Version
 * Target Section: config system global
 * Rule: Flag WARN if strong-crypto is disable/unset or ssl-min-proto-version is legacy (ssl3, tls1-0, tls1-1).
 * Flag PASS if strong-crypto is enable and minimum TLS version is >= TLSv1-2.
 */
function extractSystemGlobalScope(text) {
  if (!text) return "";

  // 1. If Multi-VDOM with 'config global', extract inside 'config global ... end'
  const multiVdomMatch = /(?:^|\n)\s*config\s+global\b([\s\S]*?)(?:\n\s*end\b|$)/i.exec(text);
  const targetScope = multiVdomMatch ? multiVdomMatch[1] : text;

  // 2. Extract 'config system global ... end' block
  const confBlockMatch = /(?:^|\n)\s*config\s+system\s+global\b([\s\S]*?)(?:\n\s*end\b|$)/i.exec(targetScope);
  if (confBlockMatch) {
    return confBlockMatch[1];
  }

  // 3. Extract CLI output: 'get system global' or 'show [full-configuration] system global'
  const cliBlockMatch = /(?:^|\n)[^\n#$]*[#$]\s*(?:get|show(?:\s+full-configuration)?)\s+system\s+global\b([\s\S]*?)(?=(?:\r?\n)[^\n#$]+[#$]|\r?\n\s*end\b|$)/i.exec(text);
  if (cliBlockMatch) {
    return cliBlockMatch[1];
  }

  // Fallback: If 'get system global' appeared without prompt prefix
  const getGlobalMatch = /(?:^|\n)\s*get\s+system\s+global\b([\s\S]*?)(?=(?:\r?\n)[^\n#$]+[#$]|\r?\n\s*(?:get|show|diagnose|config)\s+|$)/i.exec(text);
  if (getGlobalMatch) {
    return getGlobalMatch[1];
  }

  return "";
}

function checkCisTlsStrongCrypto(tokenizer, text = "") {
  let strongCrypto = null;
  let sslMinVer = null;

  // 1. Evaluate Static Config (AST / Tokenizer)
  if (tokenizer) {
    strongCrypto = cleanVal(
      tokenizer.getSystemGlobalProperty("strong-crypto") ||
      tokenizer.getProperty("system global", "strong-crypto", "global") ||
      tokenizer.getProperty("system global", "strong-crypto") || ""
    ) || null;

    sslMinVer = cleanVal(
      tokenizer.getSystemGlobalProperty("ssl-min-proto-version") ||
      tokenizer.getSystemGlobalProperty("ssl-min-proto-ver") ||
      tokenizer.getProperty("system global", "ssl-min-proto-version", "global") ||
      tokenizer.getProperty("system global", "ssl-min-proto-ver", "global") ||
      tokenizer.getProperty("system global", "ssl-min-proto-version") ||
      tokenizer.getProperty("system global", "ssl-min-proto-ver") || ""
    ) || null;
  }

  // 2. Evaluate Runtime CLI Log & Text Fallback
  // Live CLI output takes precedence over static backup defaults
  if (text) {
    // Line-anchored match for strong-crypto: matches "strong-crypto : enable" or "set strong-crypto enable"
    // Strictly anchored to line start to avoid matching the grep command itself
    const scMatch = /(?:^|\r?\n)\s*(?:set\s+)?strong-crypto\s*[:= ]\s*([a-zA-Z0-9_-]+)/i.exec(text);
    if (scMatch) {
      const detectedVal = cleanVal(scMatch[1]).toLowerCase();
      if (detectedVal === "enable" || detectedVal === "disable") {
        strongCrypto = detectedVal;
      }
    }

    // Scoped extraction for ssl-min-proto-version in system global to prevent catching it from vpn ssl
    const globalScopeText = extractSystemGlobalScope(text);
    const searchScope = globalScopeText || text;

    if (!sslMinVer) {
      const cliVerMatch = /(?:^|\r?\n)\s*ssl-min-proto-version\s*[:= ]\s*([a-zA-Z0-9_.-]+)/i.exec(searchScope);
      if (cliVerMatch) {
        sslMinVer = cleanVal(cliVerMatch[1]);
      } else if (globalScopeText) {
        const confVerMatch = /(?:^|\r?\n)\s*set\s+(?:ssl-min-proto-version|ssl-min-proto-ver)\s+([a-zA-Z0-9_.-]+)/i.exec(globalScopeText);
        if (confVerMatch) {
          sslMinVer = cleanVal(confVerMatch[1]);
        }
      }
    }
  }

  const hasGlobal = tokenizer
    ? (!!tokenizer.getSystemSection("system global") || !!tokenizer.getSection("system global"))
    : (/(?:system\s+global|strong-crypto|ssl-min)/i.test(text));
  const src = tokenizer ? "conf" : "cli";
  const remCli = "config system global\n    set strong-crypto enable\n    set ssl-min-proto-version TLSv1-2\nend";

  if (!hasGlobal && strongCrypto === null && sslMinVer === null) {
    return makeFinding({
      id: "CIS-TLS-01",
      component: "Strong Crypto & TLS Protocol Version",
      status: "NOT_EVALUATED",
      category: "CIS Benchmark",
      source: src,
      data: {},
      findingText: "Control not evaluated: Section 'config system global' is missing from configuration backup.",
      actionText: "Audit strong crypto and TLS minimum protocol version settings in 'config system global'.",
      remediationCli: remCli,
    });
  }

  const isStrongCryptoCompliant = !!strongCrypto && strongCrypto.toLowerCase() === "enable";
  const isStrongCryptoDisabled = !isStrongCryptoCompliant;

  const fullText = (tokenizer && tokenizer.rawText) ? tokenizer.rawText : text;
  const isExplicitLegacyOs = /(?:#config-version=[^:\r\n]*?[-_ ]|[vV]|Version:\s*.*?)([56]\.[0-9]+)/i.test(fullText);
  const isFortiOS7 = !isExplicitLegacyOs;

  // If ssl-min-proto-version is unset on FortiOS 7.x, treat it as factory default TLSv1-2
  const isSslMinVerUnset = !sslMinVer;
  let effectiveTlsVer = sslMinVer;
  if (isSslMinVerUnset && isFortiOS7) {
    effectiveTlsVer = "TLSv1-2";
  }

  const normTls = (effectiveTlsVer || "").toUpperCase().replace(/[._]/g, "-");
  const isLegacyTls = !effectiveTlsVer || /^(SSL3|SSLV3|TLS1-0|TLS1-1|TLSV1|TLSV1-0|TLSV1-1)$/i.test(normTls);

  const strongCryptoDisplay = strongCrypto ? strongCrypto.toLowerCase() : "disable/unset";
  const tlsVerDisplay = sslMinVer
    ? sslMinVer
    : (isFortiOS7 ? "unset (FortiOS 7.x default: TLSv1-2)" : "unset (default: TLS 1.1)");

  if (isStrongCryptoDisabled || isLegacyTls) {
    const lines = [
      "Location: config system global",
      `Detected Settings: strong-crypto = ${strongCryptoDisplay} | ssl-min-proto-version = ${tlsVerDisplay}`,
      ""
    ];

    const risks = [];
    if (isStrongCryptoDisabled) {
      risks.push(
        "• strong-crypto is disabled/unset: Permits weak and medium cryptographic ciphers (such as 3DES, RC4, DES, and CBC-mode ciphers susceptible to SWEET32 and BEAST attacks)."
      );
    }
    if (isLegacyTls) {
      const allowedProtos = !sslMinVer
        ? "TLS 1.1, TLS 1.0, and SSL 3.0"
        : /^(tls1[-._]?1|tlsv1[-._]?1)$/i.test(sslMinVer)
        ? "TLS 1.1, TLS 1.0, and SSL 3.0"
        : /^(tls1[-._]?0|tlsv1[-._]?0|tlsv1)$/i.test(sslMinVer)
        ? "TLS 1.0 and SSL 3.0"
        : "SSL 3.0";
      risks.push(
        `• ssl-min-proto-version is legacy (${tlsVerDisplay}): Permits deprecated protocol negotiation (${allowedProtos}) vulnerable to POODLE, BEAST, and eavesdropping.`
      );
    }

    lines.push("Risk Analysis:", ...risks);

    return makeFinding({
      id: "CIS-TLS-01",
      component: "Strong Crypto & TLS Protocol Version",
      status: "WARN",
      category: "CIS Benchmark",
      source: src,
      data: { strongCrypto: strongCryptoDisplay, sslMinVer: tlsVerDisplay, isStrongCryptoDisabled, isLegacyTls },
      findingText: lines.join("\n"),
      actionText: "Enable strong-crypto and enforce minimum TLS protocol version TLSv1-2 in system global to secure administrator sessions against weak cipher exploitation.",
      remediationCli: remCli,
    });
  }

  return makeFinding({
    id: "CIS-TLS-01",
    component: "Strong Crypto & TLS Protocol Version",
    status: "PASS",
    category: "CIS Benchmark",
    source: src,
    data: { strongCrypto: "enable", sslMinVer: tlsVerDisplay },
    findingText: `Location: config system global\nDetected Settings: strong-crypto = enable | ssl-min-proto-version = ${tlsVerDisplay}\nStrong cryptographic ciphers enforced and legacy TLS protocols (TLS 1.0/1.1, SSL 3.0) disabled.`,
    actionText: "",
    remediationCli: "",
  });
}

/**
 * CIS-CERT-01: Factory Default Certificates
 * Target Sections: config system global (admin-server-cert) & config vpn ssl settings (servercert)
 * Rule: Flag WARN if either certificate is set to "Fortinet_Factory" or default self-signed cert.
 * Flag PASS if custom/commercial CA-signed certificates are referenced.
 */
function checkCisCertFactoryDefault(tokenizer, text = "") {
  let adminCert = tokenizer ? cleanVal(tokenizer.getSystemGlobalProperty("admin-server-cert") || tokenizer.getProperty("system global", "admin-server-cert") || "") : null;
  let sslCert = tokenizer ? cleanVal(tokenizer.getProperty("vpn ssl settings", "servercert") || "") : null;
  if (sslCert === null && tokenizer) {
    for (const v of tokenizer.getAllVdoms()) {
      const c = tokenizer.getProperty("vpn ssl settings", "servercert", v);
      if (c) { sslCert = cleanVal(c); break; }
    }
  }

  if (adminCert === null && text) {
    const m = /set\s+admin-server-cert\s+(?:"([^"]+)"|(\S+))/i.exec(text);
    if (m) adminCert = cleanVal(m[1] || m[2]);
  }
  if (sslCert === null && text) {
    const m = /config\s+vpn\s+ssl\s+settings[\s\S]*?set\s+servercert\s+(?:"([^"]+)"|(\S+))/i.exec(text);
    if (m) sslCert = cleanVal(m[1] || m[2]);
  }

  const hasGlobalOrVpn = tokenizer
    ? (!!tokenizer.getSystemSection("system global") || !!tokenizer.getSection("system global") || !!tokenizer.getSection("vpn ssl settings"))
    : /(?:config\s+system\s+global|config\s+vpn\s+ssl\s+settings)/i.test(text);
  const src = tokenizer ? "conf" : "cli";

  if (!hasGlobalOrVpn && adminCert === null && sslCert === null) {
    return makeFinding({
      id: "CIS-CERT-01",
      component: "Factory Default Certificates",
      status: "NOT_EVALUATED",
      category: "CIS Benchmark",
      source: src,
      data: {},
      findingText: "Control not evaluated: Sections 'config system global' and 'config vpn ssl settings' are missing from configuration backup.",
      actionText: "Deploy and audit CA-signed certificates for administrative GUI and SSL-VPN gateway.",
      remediationCli: "config system global\n    set admin-server-cert <cert-name>\nend\nconfig vpn ssl settings\n    set servercert <cert-name>\nend",
    });
  }

  const offendingTargets = [];

  if (!adminCert || /^Fortinet_Factory/i.test(adminCert)) {
    offendingTargets.push("GUI Admin");
  }
  if (sslCert && /^Fortinet_Factory/i.test(sslCert)) {
    offendingTargets.push("SSL-VPN");
  }

  if (offendingTargets.length > 0) {
    return makeFinding({
      id: "CIS-CERT-01",
      component: "Factory Default Certificates",
      status: "WARN",
      category: "CIS Benchmark",
      source: src,
      data: { adminCert, sslCert, offendingTargets },
      findingText: `Factory default self-signed certificate ("Fortinet_Factory") in active use for [${offendingTargets.join(" / ")}]. Increases risk of Man-in-the-Middle (MitM) attacks and browser security bypasses.`,
      actionText: "Deploy and bind custom CA-signed certificates for administrative GUI access and SSL-VPN gateway to eliminate default self-signed certificate vulnerabilities.",
      remediationCli: "config system global\n    set admin-server-cert <cert-name>\nend\nconfig vpn ssl settings\n    set servercert <cert-name>\nend",
    });
  }

  return makeFinding({
    id: "CIS-CERT-01",
    component: "Factory Default Certificates",
    status: "PASS",
    category: "CIS Benchmark",
    source: src,
    data: { adminCert, sslCert, offendingTargets: [] },
    findingText: "Custom/Enterprise CA certificates configured for Administrative GUI and SSL-VPN.",
    actionText: "",
    remediationCli: "",
  });
}

/**
 * Runtime Checks Indicator:
 * Clearly flag dynamic operational checks when static config is uploaded without live CLI data.
 */
function makeRuntimeConfigIndicator() {
  return makeFinding(
    "RUNTIME-INFO",
    "Operational Runtime Status",
    "INFO",
    "[INFO] Static Config Uploaded - Run live CLI commands on the unit to check operational runtime status.",
    "Copy daily health check commands from the 'SecOps CLI Cheat Sheet' tab and run on the live firewall to audit Uptime, CPU/Memory, HA sync, IPSec, and SD-WAN.",
    "conf"
  );
}

// =====================================================================
// DEDUPLICATION ENGINE (Keyed by Check ID)
// Resolution Rules:
// 1. Highest severity wins: FAIL > WARN > PASS > INFO
// 2. Prefer Live CLI runtime data if available
// 3. Merge unique details cleanly without repetition
// =====================================================================
function deduplicateFindings(rawFindings) {
  const specificAppliances = new Set();
  for (const f of rawFindings) {
    const rawDev = normalizeApplianceName(f.appliance || f.deviceId || f.deviceName, "");
    if (rawDev && rawDev !== "Primary-FW" && rawDev !== "default" && rawDev !== ":") {
      specificAppliances.add(rawDev);
    }
  }
  const singleAppliance = specificAppliances.size === 1 ? [...specificAppliances][0] : null;

  const grouped = new Map();

  for (const f of rawFindings) {
    let devId = normalizeApplianceName(f.appliance || f.deviceId || f.deviceName, "Primary-FW");
    if ((devId === "Primary-FW" || devId === "default" || !devId) && singleAppliance) {
      devId = singleAppliance;
    }
    f.deviceId = devId;
    f.deviceName = devId;
    f.appliance = devId;

    const dedupKey = `${devId}::${f.id}`;
    if (!grouped.has(dedupKey)) {
      grouped.set(dedupKey, []);
    }
    grouped.get(dedupKey).push(f);
  }

  const deduped = [];

  for (const [key, list] of grouped.entries()) {
    if (list.length === 1) {
      const item = list[0];
      const finalDev = normalizeApplianceName(item.appliance || item.deviceId || item.deviceName, "Primary-FW");
      item.deviceId = finalDev;
      item.deviceName = finalDev;
      item.appliance = finalDev;
      deduped.push(item);
      continue;
    }

    // 1. Find highest severity rank
    let highestRank = 0;
    for (const item of list) {
      const rank = SEVERITY_RANK[item.status] || 0;
      if (rank > highestRank) highestRank = rank;
    }

    // Filter items with highest severity
    const highestItems = list.filter(
      (item) => (SEVERITY_RANK[item.status] || 0) === highestRank
    );

    // 2. Prefer Live CLI runtime data if available
    const preferred =
      highestItems.find((item) => item.source === "cli") ||
      highestItems[0];

    // 3. Merge unique details cleanly (strictly within the same status to prevent cross-status corruption)
    const sameStatusItems = highestItems.filter((item) => item.status === preferred.status);
    const uniqueFindingTexts = [
      ...new Set(sameStatusItems.map((item) => (item.findingText || "").trim()).filter(Boolean)),
    ];

    let mergedFindingText = preferred.findingText || "";
    if (uniqueFindingTexts.length > 1) {
      const others = uniqueFindingTexts.filter(
        (t) => t !== preferred.findingText && !preferred.findingText.includes(t)
      );
      if (others.length > 0) {
        mergedFindingText = `${preferred.findingText} (Additional Source: ${others.join("; ")})`;
      }
    }

    // Merge SOC Action
    const actions = list.map((item) => item.actionText).filter(Boolean);
    const uniqueActions = [...new Set(actions)];
    const mergedAction = uniqueActions.length > 0 ? uniqueActions[0] : "";

    // Preserve remediationCli and category
    const remediationCli = preferred.remediationCli || (list.find((i) => i.remediationCli) || {}).remediationCli || "";
    const category = preferred.category || (list.find((i) => i.category) || {}).category || (preferred.id.startsWith("CIS-") ? "CIS Benchmark" : "SecOps Operational");

    const finalDev = normalizeApplianceName(preferred.appliance || preferred.deviceId || list[0].appliance || list[0].deviceId, "Primary-FW");
    deduped.push({
      ...preferred,
      deviceId: finalDev,
      deviceName: finalDev,
      appliance: finalDev,
      findingText: mergedFindingText,
      actionText: mergedAction,
      remediationCli,
      category,
      source: preferred.source || "merged",
      data: preferred.data || {},
    });
  }

  return deduped;
}

// =====================================================================
// Orchestration & Unified Engine Runner
// =====================================================================
function runAnalysisForDevice(deviceText, deviceId = "default") {
  const normalizedDev = normalizeApplianceName(deviceId, "Primary-FW");
  const rawFindings = [];
  let tokenizer = null;
  let syntaxParser = null;
  let ast = { global: {}, vdoms: {} };

  if (/(?:^|\n)\s*config\s+/i.test(deviceText)) {
    try {
      tokenizer = new FortiOSConfigTokenizer(deviceText);
      syntaxParser = new FortiOSSyntaxParser();
      ast = syntaxParser.tokenize(deviceText);
    } catch (err) {
      console.error("Tokenizer/AST initialization error:", err);
    }
  }

  const allChecks = [
    // Core Operational Health Checks
    { id: "FGT-SYS-01", fn: () => checkFgtSystemUptime(deviceText) },
    { id: "FGT-PERF-01", fn: () => checkFgtPerformance(deviceText) },
    { id: "FGT-MEM-02", fn: () => checkFgtMemoryConserve(deviceText) },
    { id: "FGT-SESS-01", fn: () => checkFgtSessionStat(deviceText) },
    { id: "FGT-RT-BGP-01", fn: () => checkFgtBgpSummary(deviceText) },
    { id: "FGT-RT-OSPF-01", fn: () => checkFgtOspfNeighbors(deviceText) },
    { id: "FGT-HA-01", fn: () => checkFgtHaStatus(deviceText) },
    { id: "FGT-FG-01", fn: () => checkFgtFortiGuardSync(deviceText) },
    { id: "FGT-IPSEC-01", fn: () => checkFgtIpsecTunnels(deviceText) },
    { id: "FGT-SDWAN-01", fn: () => checkFgtSdwanSla(deviceText) },
    { id: "FGT-FEED-01", fn: () => checkFgtThreatFeeds(deviceText, tokenizer) },
    { id: "FGT-NET-01", fn: () => checkFgtPhysicalInterfaces(deviceText) },
    { id: "FGT-NET-02", fn: () => checkFgtNetlinkErrorRatios(deviceText) },
    { id: "FGT-CERT-01", fn: () => checkFgtCertificates(deviceText) },
    { id: "SEC-INTF-01", fn: () => checkSecWanAdminAccess(deviceText, tokenizer) },
    { id: "SEC-USER-01", fn: () => checkSecLocalUsersMfa(deviceText, tokenizer) },
    { id: "FGT-BAN-01", fn: () => checkFgtBanList(deviceText) },
    { id: "FGT-LOG-01", fn: () => checkFgtMiglogd(deviceText) },
    { id: "FGT-SYS-03", fn: () => checkFgtCrashlogHistory(deviceText) },
    { id: "FAZ-STOR-01", fn: () => checkFazStorage(deviceText) },
    { id: "FAZ-CONN-01", fn: () => checkFazActiveDevices(deviceText) },
    { id: "FAZ-SYS-01", fn: () => checkFazSysPerformanceHa(deviceText) },
    { id: "FAZ-IDX-01", fn: () => checkFazIndexingPipeline(deviceText) },
    { id: "SEC-VIP-01", fn: () => checkSecVirtualIps(tokenizer, deviceText) },
    { id: "SEC-VPN-01", fn: () => checkSecSslVpnGeoFencing(tokenizer, deviceText) },
    // CIS Benchmark & Hardening Audits (v3.0)
    { id: "CIS-ADM-01", fn: () => checkCisAdmIdleTimeout(tokenizer, deviceText) },
    { id: "CIS-ADM-02", fn: () => checkCisAdmAccountLockout(tokenizer, deviceText) },
    { id: "CIS-ADM-03", fn: () => checkCisAdmAdminPorts(tokenizer, deviceText) },
    { id: "CIS-SYS-01", fn: () => checkCisSysHostname(tokenizer, deviceText) },
    { id: "CIS-SYS-02", fn: () => checkCisSysNtpTimezone(tokenizer, deviceText) },
    { id: "CIS-AUTH-01", fn: () => checkCisAuthPasswordPolicy(tokenizer, deviceText) },
    { id: "CIS-MGMT-01", fn: () => checkCisMgmtSnmpCommunity(tokenizer, deviceText) },
    { id: "SEC-FW-01", fn: () => checkSecFirewallAnyPolicy(tokenizer, deviceText) },
    { id: "SEC-FW-02", fn: () => checkSecInboundDangerousPorts(tokenizer, deviceText) },
    { id: "CIS-LOG-01", fn: () => checkCisLogCentralized(tokenizer, deviceText) },
    { id: "CIS-AUTH-02", fn: () => checkCisAuthTrustedHosts(tokenizer, deviceText) },
    { id: "CIS-TLS-01", fn: () => checkCisTlsStrongCrypto(tokenizer, deviceText) },
    { id: "CIS-CERT-01", fn: () => checkCisCertFactoryDefault(tokenizer, deviceText) },
    // Deep Research Checks: Static Configuration Hardening
    { id: "CIS-MED-01", fn: () => checkCisBanners(deviceText, ast) },
    { id: "CIS-HIGH-01", fn: () => checkCisAutoInstall(deviceText, ast) },
    { id: "SEC-HIGH-02", fn: () => checkSecUrpfAntiSpoofing(deviceText, ast) },
    { id: "CIS-MED-02", fn: () => checkCisDnsOverTls(deviceText, ast) },
    { id: "SEC-HIGH-01", fn: () => checkSecAdminMfa(deviceText, ast) },
    { id: "SEC-MED-01", fn: () => checkSecSslSshProfile(deviceText, ast) },
    { id: "SEC-CRIT-01", fn: () => checkSecFgfmExposure(deviceText, ast) },
    { id: "SEC-CRIT-02", fn: () => checkSecSslVpnWebMode(deviceText, ast) },
    { id: "SEC-LIFE-01", fn: () => checkSecFortiOSLifecycle(deviceText) },
    // Deep Research Checks: Operational Runtime Diagnostics
    { id: "OPS-MEM-01", fn: () => checkOpsWadWorkers(deviceText) },
    { id: "OPS-HA-01", fn: () => checkOpsHaHistory(deviceText) },
    { id: "OPS-DNS-01", fn: () => checkOpsRatingServers(deviceText) },
    { id: "OPS-BGP-01", fn: () => checkOpsBgpDampening(deviceText) },
    { id: "FAZ-FWD-01", fn: () => checkFazSilentForwarder(deviceText) },
    { id: "FAZ-DISK-01", fn: () => checkFazRaidHealth(deviceText) },
  ];

  let hasOperationalCliFinding = false;

  for (const check of allChecks) {
    try {
      const res = check.fn();
      if (res) {
        if (Array.isArray(res)) {
          for (const item of res) {
            item.deviceId = normalizeApplianceName(item.appliance || item.deviceId || normalizedDev, normalizedDev);
            item.deviceName = item.deviceId;
            item.appliance = item.deviceId;
            rawFindings.push(item);
            if (item.id.startsWith("FGT-") || item.id.startsWith("FAZ-") || item.id.startsWith("OPS-")) {
              hasOperationalCliFinding = true;
            }
          }
        } else {
          res.deviceId = normalizeApplianceName(res.appliance || res.deviceId || normalizedDev, normalizedDev);
          res.deviceName = res.deviceId;
          res.appliance = res.deviceId;
          rawFindings.push(res);
          if (res.id.startsWith("FGT-") || res.id.startsWith("FAZ-") || res.id.startsWith("OPS-")) {
            hasOperationalCliFinding = true;
          }
        }
      }
    } catch (err) {
      console.error(`Check execution error in ${check.id}:`, err);
      rawFindings.push(makeFinding({
        id: check.id,
        component: check.id,
        status: "ERROR",
        category: check.id.startsWith("CIS-") ? "CIS Benchmark" : (check.id.startsWith("SEC-") ? "Security & Hardening" : "SecOps Operational"),
        source: tokenizer ? "conf" : "cli",
        deviceId: normalizedDev,
        appliance: normalizedDev,
        findingText: `[ERROR] [${check.id}] Check execution failed: ${err && err.message ? err.message : String(err)}. Please report this to SecOps engineering.`,
        actionText: "Report the unhandled configuration structure to SecOps engineering for parser resolution.",
      }));
    }
  }

  // Include Runtime Checks Indicator if static config was analyzed with no live operational CLI data
  if (tokenizer && !hasOperationalCliFinding && rawFindings.length > 0) {
    const rInfo = makeRuntimeConfigIndicator();
    rInfo.deviceId = normalizedDev;
    rInfo.deviceName = normalizedDev;
    rInfo.appliance = normalizedDev;
    rawFindings.push(rInfo);
  }

  return rawFindings;
}

function runAnalysis(rawText, fileChunks = []) {
  let allRawFindings = [];

  if (fileChunks && fileChunks.length > 1) {
    for (const chunk of fileChunks) {
      const devId = extractDeviceIdentity(chunk.content, chunk.name || "device");
      const findings = runAnalysisForDevice(chunk.content, devId);
      allRawFindings.push(...findings);
    }
  } else {
    // Check if rawText contains multiple #config-version boundaries
    const splitRegex = /(?=(?:^|\n)#config-version=[^\r\n]+)/g;
    const parts = rawText.split(splitRegex).filter((p) => p.trim().length > 0);
    if (parts.length > 1) {
      parts.forEach((part, idx) => {
        const devId = extractDeviceIdentity(part, `device-${idx + 1}`);
        const findings = runAnalysisForDevice(part, devId);
        allRawFindings.push(...findings);
      });
    } else {
      const devId = extractDeviceIdentity(rawText, (fileChunks && fileChunks[0] && fileChunks[0].name) ? fileChunks[0].name : "Primary-FW");
      allRawFindings = runAnalysisForDevice(rawText, devId);
    }
  }

  return deduplicateFindings(allRawFindings);
}

// =====================================================================
// EXPORT GENERATORS (Clean Clipboard & Downloads, NO RAW **)
// =====================================================================

// =====================================================================
// =====================================================================
// LOCALIZATION STRINGS (ENGLISH OPEN SOURCE EDITION)
// =====================================================================

const UI_STRINGS = {
  en: {
    titleMain: "FortiOS Security & Hardening Auditor",
    brandSub: "Fortinet Security Operations & Compliance Auditor",
    tabAnalyzer: "Security Audit & Inspector",
    tabCheatsheet: "Diagnostic CLI Cheat Sheet",
    labelPass: "PASS",
    labelWarn: "WARN",
    labelFail: "FAIL",
    dropzonePrimary: 'Drop .log/.conf files or <span class="browse-link">browse</span>',
    dropzoneSub: "Drop configuration backups (.conf/.cfg) or diagnostic CLI logs (.txt/.log)",
    pasteToggle: "Direct Paste / Terminal Session",
    analyzeBtn: "Analyze Security",
    clearBtn: "Clear",
    resultsHeading: "Findings & Security Audit",
    filterIssues: "Issues Only (FAIL & WARN)",
    btnRich: "Copy Rich Text",
    btnPlain: "Plain Text",
    thCheckId: "Control ID",
    thComponent: "Component",
    thStatus: "Status",
    thFindings: "Audit Findings & Security Action",
    emptyTitle: "Ready for Security & Hardening Audit",
    emptyDesc: "Drop FortiOS configuration backups (.conf/.cfg) or diagnostic CLI logs (.txt/.log) above, then click <strong>Analyze Security</strong>.",
    cheatsheetTitle: "Standard Diagnostic & Status Commands",
    cheatsheetDesc: "Standardized diagnostic and status command blocks for FortiGate Firewalls and FortiAnalyzer appliances. Click <strong>Copy Verified 1-Click Bundle</strong> to paste into your terminal, or click individual commands.",
    toastCopiedRich: "Copied Rich Text report to clipboard!",
    toastCopiedPlain: "Copied clean plain text report to clipboard!",
    toastDownloaded: "Audit report downloaded successfully.",
    toastNoIssues: "All checks passed! No issues to copy.",
    toastCopiedCli: "Remediation CLI copied to clipboard!",
    actionPrefix: "Security Action:",
    remediationLabel: "Remediation CLI:",
    btnCopyCli: "Copy CLI",
    labelCisScore: "CIS Score",
    detectBadge: {
      none: "No input",
      fgt: "FGT Live CLI",
      faz: "FAZ Live CLI",
      dual: "Dual FGT+FAZ",
      conf: "FortiOS Static Config",
    },
  },
};

function getLocalizedFinding(f) {
  return {
    ...f,
    statusLabel: f.status,
    findingText: f.findingText || renderFindingText(f, "en"),
    actionText: f.actionText || renderFindingAction(f, "en"),
  };
}

function extractDeviceMetadata(findings = [], kind = "conf", text = "") {
  let hostname = "";
  let firmware = "";
  let serial = "";

  // 1. Try findingText from findings (e.g. FGT-SYS-01 or CIS-SYS-01)
  for (const f of findings) {
    if (f.id === "FGT-SYS-01" || f.id === "CIS-SYS-01") {
      const hMatch = /(?:Hostname:\s*|hostname configured:\s*["']?|hostname detected:\s*["']?)([^\s,|"']+)/i.exec(f.findingText);
      if (hMatch && !hostname && hMatch[1] !== ":") hostname = normalizeApplianceName(hMatch[1], "");
      const vMatch = /(?:Version|Firmware):\s*([^\n,|]+)/i.exec(f.findingText);
      if (vMatch && !firmware) firmware = vMatch[1].trim();
      const sMatch = /Serial(?:-Number)?:\s*([A-Z0-9]+)/i.exec(f.findingText);
      if (sMatch && !serial) serial = sMatch[1].trim();
    }
    if (!hostname && f.appliance && f.appliance !== ":" && f.appliance !== "Primary-FW" && f.appliance !== "default") {
      hostname = normalizeApplianceName(f.appliance, "");
    }
  }

  // 2. Try raw text regexes
  if (text) {
    if (!hostname) {
      const appMatch = /(?:^|\s|,|;)(?:appliance|devname)\s*[:=]\s*["']?([^"'\r\n\s,;]+)["']?/i.exec(text);
      if (appMatch && appMatch[1] && appMatch[1].trim() !== ":") {
        hostname = normalizeApplianceName(appMatch[1], "");
      }
    }
    if (!hostname) {
      const hm = /(?:set\s+hostname\s+["']?([^"'\r\n]+)["']?|Hostname:\s*([^\r\n]+))/i.exec(text);
      if (hm) {
        const rawH = (hm[1] || hm[2]).trim().replace(/^[:\s"']+|[:\s"']+$/g, "");
        if (rawH && rawH !== ":") hostname = normalizeApplianceName(rawH, "");
      }
    }
    if (!firmware) {
      const cfgVer = /#config-version=([^\r\n:]+)/i.exec(text);
      if (cfgVer) {
        firmware = cfgVer[1].trim();
      } else {
        const vm = /Version:\s*([^\r\n]+)/i.exec(text);
        if (vm) firmware = vm[1].trim();
      }
    }
    if (!serial) {
      const sm = /(?:Serial-Number|Serial):\s*([A-Z0-9]+)/i.exec(text);
      if (sm) serial = sm[1].trim();
    }
  }

  const resolvedName = hostname || "FortiGate-Appliance";
  return {
    hostname: resolvedName,
    appliance: resolvedName,
    firmware: firmware || "FortiOS 7.x (Hardening Baseline)",
    serial: serial || "Not Disclosed (Static Config)",
    auditorEngine: "SecOps Security Engine v3.2",
    auditTimestamp: new Date().toISOString().replace("T", " ").substring(0, 19) + " UTC",
  };
}

function getCheckConfigPath(f) {
  return (f && f.targetConfig) || getFindingTargetConfig(f);
}

/**
 * Maps finding or check ID to its FortiOS configuration path or CLI context.
 */
function getFindingTargetConfig(f) {
  if (!f) return "config system global";
  if (f.targetConfig) return f.targetConfig;
  if (f.findingText) {
    const locMatch = /Location:\s*([^\n\r|]+)/i.exec(f.findingText);
    if (locMatch) return locMatch[1].trim();
  }
  const id = f.id || (typeof f === 'string' ? f : '');
  const configMap = {
    "CIS-ADM-01": "config system global",
    "CIS-ADM-02": "config system global",
    "CIS-ADM-03": "config system global",
    "CIS-AUTH-01": "config system password-policy",
    "CIS-AUTH-02": "config system admin",
    "CIS-AUTH-03": "config system global",
    "CIS-TLS-01": "config system global",
    "CIS-CERT-01": "config vpn ssl settings",
    "CIS-MGMT-01": "config system snmp community",
    "CIS-MGMT-02": "config system snmp sysinfo",
    "CIS-LOG-01": "config log fortianalyzer setting",
    "CIS-SYS-01": "config system global",
    "CIS-SYS-02": "config system ntp",
    "CIS-NTP-01": "config system ntp",
    "CIS-HIGH-01": "config system auto-install",
    "CIS-MED-01": "config system global",
    "CIS-MED-02": "config system dns",
    "SEC-VIP-01": "config firewall vip",
    "SEC-VPN-01": "config vpn ssl settings",
    "SEC-FW-01": "config firewall policy",
    "SEC-FW-02": "config firewall policy",
    "SEC-USER-01": "config user local",
    "SEC-INTF-01": "config system interface",
    "SEC-HIGH-01": "config system admin",
    "SEC-HIGH-02": "config system settings",
    "SEC-MED-01": "config firewall ssl-ssh-profile",
    "SEC-CRIT-01": "config system interface",
    "SEC-CRIT-02": "config vpn ssl web portal",
    "SEC-CRIT-03": "get system status",
    "SEC-LIFE-01": "get system status",
    "OPS-HIGH-01": "diagnose test application wad 1000",
    "OPS-MEM-01": "diagnose test application wad 1000",
    "OPS-HIGH-02": "diagnose sys ha history read",
    "OPS-HA-01": "diagnose sys ha history read",
    "OPS-MED-01": "diagnose debug rating",
    "OPS-DNS-01": "diagnose debug rating",
    "OPS-MED-02": "get router info bgp dampening flap-statistics",
    "OPS-BGP-01": "get router info bgp dampening flap-statistics",
    "FAZ-HIGH-01": "diagnose fortilogd lograte-device",
    "FAZ-FWD-01": "diagnose fortilogd lograte-device",
    "FAZ-CRIT-01": "diagnose system raid status",
    "FAZ-DISK-01": "diagnose system raid status",
    "FGT-SYS-01": "get system status",
    "FGT-PERF-01": "get system performance status",
    "FGT-MEM-02": "diagnose hardware sysinfo conserve",
    "FGT-SESS-01": "diagnose sys session stat",
    "FGT-RT-BGP-01": "get router info bgp summary",
    "FGT-RT-OSPF-01": "get router info ospf neighbor",
    "FGT-HA-01": "get system ha status",
    "FGT-FG-01": "diagnose autoupdate status",
    "FGT-IPSEC-01": "get vpn ipsec tunnel summary",
    "FGT-SDWAN-01": "diagnose sys sdwan health-check",
    "FGT-FEED-01": "get system external-resource",
    "FGT-NET-01": "get system interface physical",
    "FGT-NET-02": "diagnose netlink interface list",
    "FGT-CERT-01": "get vpn certificate local details",
    "FGT-BAN-01": "diagnose user ban list",
    "FGT-LOG-01": "diagnose test application miglogd 6",
    "FGT-SYS-03": "diagnose debug crashlog read",
    "FAZ-SYS-01": "get system performance",
    "FAZ-STOR-01": "diagnose system print df",
    "FAZ-CONN-01": "diagnose test application oftpd 3",
    "FAZ-IDX-01": "diagnose fortilogd msgrate",
  };
  return configMap[id] || "config system global";
}

function formatFindingHtml(rawText) {
  if (!rawText) return "";
  const noEmojis = rawText.replace(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}\u{FE00}-\u{FE0F}]/ug, "").trim();
  const lines = noEmojis.split(/\r?\n/);
  let html = "";
  let inList = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const bulletMatch = line.match(/^\s*[•\*\-]\s+(.*)$/);
    if (bulletMatch) {
      if (!inList) {
        html += '<ul class="finding-bullets">';
        inList = true;
      }
      html += `<li>${escapeHtml(bulletMatch[1])}</li>`;
    } else {
      if (inList) {
        html += "</ul>";
        inList = false;
      }
      if (i > 0 && html.length > 0 && !html.endsWith("</ul>")) {
        html += "<br>";
      }
      html += escapeHtml(line);
    }
  }
  if (inList) {
    html += "</ul>";
  }
  return html;
}

/**
 * Generates formatted Rich Text (HTML) for ClickUp, Slack, Jira, or email.
 * Supports dual-language (EN / HE) and issues-only filtering.
 * NO raw Markdown characters (**, ##, ---).
 * Emojis eliminated in favor of clean, executive typography and badges.
 */
function generateRichTextHtml(findings, kind, options = {}) {
  const issuesOnly = options.issuesOnly || false;

  let activeFindings = issuesOnly
    ? findings.filter((f) => f.status === "FAIL" || f.status === "WARN")
    : findings;

  const passCount = activeFindings.filter((f) => f.status === "PASS").length;
  const warnCount = activeFindings.filter((f) => f.status === "WARN").length;
  const failCount = activeFindings.filter((f) => f.status === "FAIL").length;

  const metadata = extractDeviceMetadata(findings, kind, options.rawText || "");

  const scopeMap = {
    fgt: "FortiGate Live CLI Diagnostics",
    faz: "FortiAnalyzer Live CLI Diagnostics",
    dual: "FortiGate + FortiAnalyzer Live Dual Audit",
    conf: "FortiOS Static Configuration Hardening",
    none: "SecOps Security Inspection",
  };

  const fails = activeFindings.filter((f) => f.status === "FAIL");
  const warns = activeFindings.filter((f) => f.status === "WARN");
  const passes = activeFindings.filter((f) => f.status === "PASS");
  const infos = activeFindings.filter((f) => f.status === "INFO");

  const dirAttr = 'dir="ltr"';
  const textAlign = "text-align: left;";
  const actionBorder = "border-left: 3px solid #10b981; border-right: none; border-radius: 0 4px 4px 0;";

  const hasCisScore = options.profile === "cis" && typeof options.cisScore === "number";
  const scoreColor = hasCisScore
    ? (options.cisScore >= 85 ? "#059669" : options.cisScore >= 70 ? "#d97706" : "#dc2626")
    : "#475569";

  let html = `
<div ${dirAttr} style="direction: ${"ltr"}; ${textAlign} font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; font-size: 13px; line-height: 1.5; color: #1e293b;">
  <div style="border-bottom: 2px solid #0284c7; padding-bottom: 8px; margin-bottom: 12px;">
    <div style="font-size: 11px; font-weight: 700; color: #0284c7; text-transform: uppercase; letter-spacing: 0.5px;">${"EXECUTIVE SOC AUDIT DELIVERABLE"}</div>
    <h2 style="margin: 2px 0 4px 0; color: #0f172a; font-size: 18px; font-weight: 700;">
      ${"SecOps Health Check & Security Audit Report"}
    </h2>
    <div style="font-size: 12px; color: #64748b;">${escapeHtml(scopeMap[kind] || ("Fortinet Infrastructure"))} | ${metadata.auditTimestamp}</div>
  </div>

  <table style="width: 100%; border-collapse: collapse; margin-bottom: 14px; font-size: 12px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px;">
    <tr>
      <td style="padding: 6px 10px; border: 1px solid #e2e8f0; font-weight: 600; color: #475569; width: 20%;">${"Hostname:"}</td>
      <td style="padding: 6px 10px; border: 1px solid #e2e8f0; color: #0f172a; font-weight: 600; width: 30%;">${escapeHtml(metadata.hostname)}</td>
      <td style="padding: 6px 10px; border: 1px solid #e2e8f0; font-weight: 600; color: #475569; width: 20%;">${"Firmware / Build:"}</td>
      <td style="padding: 6px 10px; border: 1px solid #e2e8f0; color: #0f172a; width: 30%;">${escapeHtml(metadata.firmware)}</td>
    </tr>
    <tr>
      <td style="padding: 6px 10px; border: 1px solid #e2e8f0; font-weight: 600; color: #475569;">${"Serial Number:"}</td>
      <td style="padding: 6px 10px; border: 1px solid #e2e8f0; color: #0f172a; font-family: monospace;">${escapeHtml(metadata.serial)}</td>
      <td style="padding: 6px 10px; border: 1px solid #e2e8f0; font-weight: 600; color: #475569;">${"Auditor Engine:"}</td>
      <td style="padding: 6px 10px; border: 1px solid #e2e8f0; color: #0f172a;">${escapeHtml(metadata.auditorEngine)}</td>
    </tr>
    ${hasCisScore ? `
    <tr>
      <td style="padding: 6px 10px; border: 1px solid #e2e8f0; font-weight: 600; color: #475569;">${"CIS Score:"}</td>
      <td colspan="3" style="padding: 6px 10px; border: 1px solid #e2e8f0; font-weight: 700; color: ${scoreColor};">
        <span class="metric-cis">${options.cisScore}%</span> (${options.totalPassed || 0}/${options.totalEvaluated || 0} ${"controls passed"})
      </td>
    </tr>` : ""}
  </table>

  <div style="display: flex; gap: 8px; margin-bottom: 16px; font-size: 12px;">
    <div style="flex: 1; padding: 8px 10px; background: #fef2f2; border: 1px solid #fecaca; border-radius: 4px; text-align: center;">
      <div style="color: #dc2626; font-weight: 700; font-size: 15px;">${failCount}</div>
      <div style="color: #991b1b; font-size: 10.5px; text-transform: uppercase; font-weight: 600;">${"Critical / Fail"}</div>
    </div>
    <div style="flex: 1; padding: 8px 10px; background: #fffbeb; border: 1px solid #fde68a; border-radius: 4px; text-align: center;">
      <div style="color: #d97706; font-weight: 700; font-size: 15px;">${warnCount}</div>
      <div style="color: #92400e; font-size: 10.5px; text-transform: uppercase; font-weight: 600;">${"Warnings"}</div>
    </div>
    ${!issuesOnly ? `
    <div style="flex: 1; padding: 8px 10px; background: #ecfdf5; border: 1px solid #a7f3d0; border-radius: 4px; text-align: center;">
      <div style="color: #059669; font-weight: 700; font-size: 15px;">${passCount}</div>
      <div style="color: #065f46; font-size: 10.5px; text-transform: uppercase; font-weight: 600;">${"Passing"}</div>
    </div>` : ""}
  </div>
`;

  if (fails.length > 0) {
    html += `
  <h3 style="margin: 16px 0 8px 0; font-size: 13.5px; font-weight: 700; color: #dc2626; border-bottom: 1px solid #fee2e2; padding-bottom: 4px;">
    ${`Critical Items Requiring Immediate SOC Action (${fails.length})`}
  </h3>
  <ul style="margin: 0 0 14px 0; padding-${"left"}: 20px;">
`;
    for (const f of fails) {
      const statusLabel = "CRITICAL";
      const targetConfig = getFindingTargetConfig(f);
      const diagCmd = f.diagnosticCmd || DIAGNOSTIC_COMMANDS[f.id] || "diagnose sys status";
      const devBadge = escapeHtml(f.deviceId || f.deviceName || "Primary-FW");
      html += `
    <li style="margin-bottom: 14px;">
      <div style="margin-bottom: 4px;">
        <span style="background: #fee2e2; color: #991b1b; padding: 2px 7px; border-radius: 4px; font-family: monospace; font-size: 10.5px; font-weight: 700;">${statusLabel}</span>
        <span style="background: #e0f2fe; color: #0369a1; padding: 2px 7px; border-radius: 4px; font-family: monospace; font-size: 10.5px; font-weight: 700; margin-${"left"}: 4px;">${devBadge}</span>
        <strong style="margin-${"left"}: 6px; color: #0f172a; font-size: 13px;">[${escapeHtml(f.id)}] ${escapeHtml(f.component)}</strong>
      </div>
      <div style="font-size: 11px; color: #64748b; font-family: monospace; margin: 2px 0 4px 0;"><strong>${"Diagnostic CLI:"}</strong> <code style="background: #f1f5f9; padding: 1px 5px; border-radius: 3px; color: #0284c7; margin-${"right"}: 8px;">${escapeHtml(diagCmd)}</code> <strong>${"Target Config:"}</strong> <code style="background: #f1f5f9; padding: 1px 5px; border-radius: 3px; color: #0f172a;">${escapeHtml(targetConfig)}</code></div>
      <div style="color: #334155; line-height: 1.6; font-size: 12.5px;">${formatFindingHtml(f.findingText)}</div>
      ${
        f.actionText
          ? `<div style="margin-top: 6px; padding: 6px 10px; background: #f8fafc; ${actionBorder} font-size: 12px; color: #0f172a;">
              <strong style="color: #059669; text-transform: uppercase; font-size: 10.5px;">${"SOC Action Required:"}</strong> ${escapeHtml(f.actionText)}
             </div>`
          : ""
      }
      ${
        f.remediationCli
          ? `<div style="margin-top: 6px; padding: 6px 10px; background: #0b1118; border: 1px solid #223040; border-radius: 4px; font-family: monospace; font-size: 11px; color: #38bdf8; white-space: pre; direction: ltr; text-align: left;">
              <strong style="color: #94a3b8; display: block; margin-bottom: 3px; font-size: 10px; text-transform: uppercase;">${"Remediation CLI:"}</strong>${escapeHtml(f.remediationCli)}
             </div>`
          : ""
      }
    </li>
`;
    }
    html += `  </ul>\n`;
  }

  if (warns.length > 0) {
    html += `
  <h3 style="margin: 16px 0 8px 0; font-size: 13.5px; font-weight: 700; color: #d97706; border-bottom: 1px solid #fef3c7; padding-bottom: 4px;">
    ${`Security Warnings & Operational Risks (${warns.length})`}
  </h3>
  <ul style="margin: 0 0 14px 0; padding-${"left"}: 20px;">
`;
    for (const f of warns) {
      const statusLabel = "WARNING";
      const targetConfig = getFindingTargetConfig(f);
      const diagCmd = f.diagnosticCmd || DIAGNOSTIC_COMMANDS[f.id] || "diagnose sys status";
      const devBadge = escapeHtml(f.deviceId || f.deviceName || "Primary-FW");
      html += `
    <li style="margin-bottom: 14px;">
      <div style="margin-bottom: 4px;">
        <span style="background: #fef3c7; color: #92400e; padding: 2px 7px; border-radius: 4px; font-family: monospace; font-size: 10.5px; font-weight: 700;">${statusLabel}</span>
        <span style="background: #e0f2fe; color: #0369a1; padding: 2px 7px; border-radius: 4px; font-family: monospace; font-size: 10.5px; font-weight: 700; margin-${"left"}: 4px;">${devBadge}</span>
        <strong style="margin-${"left"}: 6px; color: #0f172a; font-size: 13px;">[${escapeHtml(f.id)}] ${escapeHtml(f.component)}</strong>
      </div>
      <div style="font-size: 11px; color: #64748b; font-family: monospace; margin: 2px 0 4px 0;"><strong>${"Diagnostic CLI:"}</strong> <code style="background: #f1f5f9; padding: 1px 5px; border-radius: 3px; color: #0284c7; margin-${"right"}: 8px;">${escapeHtml(diagCmd)}</code> <strong>${"Target Config:"}</strong> <code style="background: #f1f5f9; padding: 1px 5px; border-radius: 3px; color: #0f172a;">${escapeHtml(targetConfig)}</code></div>
      <div style="color: #334155; line-height: 1.6; font-size: 12.5px;">${formatFindingHtml(f.findingText)}</div>
      ${
        f.actionText
          ? `<div style="margin-top: 6px; padding: 6px 10px; background: #f8fafc; ${actionBorder} font-size: 12px; color: #0f172a;">
              <strong style="color: #059669; text-transform: uppercase; font-size: 10.5px;">${"SOC Action Required:"}</strong> ${escapeHtml(f.actionText)}
             </div>`
          : ""
      }
      ${
        f.remediationCli
          ? `<div style="margin-top: 6px; padding: 6px 10px; background: #0b1118; border: 1px solid #223040; border-radius: 4px; font-family: monospace; font-size: 11px; color: #38bdf8; white-space: pre; direction: ltr; text-align: left;">
              <strong style="color: #94a3b8; display: block; margin-bottom: 3px; font-size: 10px; text-transform: uppercase;">${"Remediation CLI:"}</strong>${escapeHtml(f.remediationCli)}
             </div>`
          : ""
      }
    </li>
`;
    }
    html += `  </ul>\n`;
  }

  if (!issuesOnly && passes.length > 0) {
    html += `
  <h3 style="margin: 16px 0 8px 0; font-size: 13.5px; font-weight: 700; color: #059669; border-bottom: 1px solid #d1fae5; padding-bottom: 4px;">
    ${`Verified Healthy Controls & Passing Checks (${passes.length})`}
  </h3>
  <ul style="margin: 0 0 14px 0; padding-${"left"}: 20px;">
`;
    for (const f of passes) {
      const statusLabel = "PASS";
      const targetConfig = getFindingTargetConfig(f);
      const diagCmd = f.diagnosticCmd || DIAGNOSTIC_COMMANDS[f.id] || "diagnose sys status";
      const devBadge = escapeHtml(f.deviceId || f.deviceName || "Primary-FW");
      html += `
    <li style="margin-bottom: 10px;">
      <div style="margin-bottom: 4px;">
        <span style="background: #d1fae5; color: #065f46; padding: 2px 7px; border-radius: 4px; font-family: monospace; font-size: 10.5px; font-weight: 700;">${statusLabel}</span>
        <span style="background: #e0f2fe; color: #0369a1; padding: 2px 7px; border-radius: 4px; font-family: monospace; font-size: 10.5px; font-weight: 700; margin-${"left"}: 4px;">${devBadge}</span>
        <strong style="margin-${"left"}: 6px; color: #0f172a; font-size: 13px;">[${escapeHtml(f.id)}] ${escapeHtml(f.component)}</strong>
      </div>
      <div style="font-size: 11px; color: #64748b; font-family: monospace; margin: 2px 0 4px 0;"><strong>${"Diagnostic CLI:"}</strong> <code style="background: #f1f5f9; padding: 1px 5px; border-radius: 3px; color: #0284c7; margin-${"right"}: 8px;">${escapeHtml(diagCmd)}</code> <strong>${"Target Config:"}</strong> <code style="background: #f1f5f9; padding: 1px 5px; border-radius: 3px; color: #0f172a;">${escapeHtml(targetConfig)}</code></div>
      <div style="color: #334155; line-height: 1.6; font-size: 12.5px;">${formatFindingHtml(f.findingText)}</div>
    </li>
`;
    }
    html += `  </ul>\n`;
  }

  if (!issuesOnly && infos.length > 0) {
    html += `
  <h3 style="margin: 16px 0 8px 0; font-size: 13.5px; font-weight: 700; color: #0284c7; border-bottom: 1px solid #e0f2fe; padding-bottom: 4px;">
    ${"SecOps Operational Guidance"}
  </h3>
  <ul style="margin: 0 0 14px 0; padding-${"left"}: 20px;">
`;
    for (const f of infos) {
      const statusLabel = "INFO";
      const targetConfig = getFindingTargetConfig(f);
      const diagCmd = f.diagnosticCmd || DIAGNOSTIC_COMMANDS[f.id] || "diagnose sys status";
      const devBadge = escapeHtml(f.deviceId || f.deviceName || "Primary-FW");
      html += `
    <li style="margin-bottom: 10px;">
      <div style="margin-bottom: 4px;">
        <span style="background: #e0f2fe; color: #075985; padding: 2px 7px; border-radius: 4px; font-family: monospace; font-size: 10.5px; font-weight: 700;">${statusLabel}</span>
        <span style="background: #e0f2fe; color: #0369a1; padding: 2px 7px; border-radius: 4px; font-family: monospace; font-size: 10.5px; font-weight: 700; margin-${"left"}: 4px;">${devBadge}</span>
        <strong style="margin-${"left"}: 6px; color: #0f172a; font-size: 13px;">[${escapeHtml(f.id)}] ${escapeHtml(f.component)}</strong>
      </div>
      <div style="font-size: 11px; color: #64748b; font-family: monospace; margin: 2px 0 4px 0;"><strong>${"Diagnostic CLI:"}</strong> <code style="background: #f1f5f9; padding: 1px 5px; border-radius: 3px; color: #0284c7; margin-${"right"}: 8px;">${escapeHtml(diagCmd)}</code> <strong>${"Target Config:"}</strong> <code style="background: #f1f5f9; padding: 1px 5px; border-radius: 3px; color: #0f172a;">${escapeHtml(targetConfig)}</code></div>
      <div style="color: #334155; line-height: 1.6; font-size: 12.5px;">${formatFindingHtml(f.findingText)}</div>
      ${
        f.actionText
          ? `<div style="margin-top: 3px; font-size: 12px; color: #475569;">${escapeHtml(f.actionText)}</div>`
          : ""
      }
    </li>
`;
    }
    html += `  </ul>\n`;
  }

  html += `
  <div style="margin-top: 18px; padding-top: 8px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8;">
    ${"Report generated by SecOps Security Engine v3.2"}
  </div>
</div>
`;

  return redactSensitiveData(html);
}

/**
 * Generates clean ASCII plain-text report.
 * Completely stripped of markdown asterisks (**), hashes (##), and markdown syntax characters.
 * Supports dual-language (EN / HE) and issues-only filtering.
 */
function generateCleanPlainText(findings, kind, options = {}) {
  const lang = options.lang || "en";
  const issuesOnly = options.issuesOnly || false;

  let activeFindings = issuesOnly
    ? findings.filter((f) => f.status === "FAIL" || f.status === "WARN")
    : findings;

  if (lang === "he") {
    activeFindings = activeFindings.map((f) => getLocalizedFinding(f, "he"));
  }

  const isHe = lang === "he";
  const dateStr = new Date().toISOString().replace("T", " ").substring(0, 19) + " UTC";
  const passCount = activeFindings.filter((f) => f.status === "PASS").length;
  const warnCount = activeFindings.filter((f) => f.status === "WARN").length;
  const failCount = activeFindings.filter((f) => f.status === "FAIL").length;

  const scopeMapEn = {
    fgt: "FortiGate Live CLI Diagnostics",
    faz: "FortiAnalyzer Live CLI Diagnostics",
    dual: "FortiGate + FortiAnalyzer Live Dual Audit",
    conf: "FortiOS Static Configuration Hardening",
    none: "SecOps Security Inspection",
  };
    const scopeMap = scopeMapEn;

  const headerTitle = "FORTIOS SECURITY & HARDENING AUDIT REPORT";
  const summaryLabel = "Summary:    ";
  const timestampLabel = "Timestamp:  ";
  const scopeLabel = "Audit Scope:";

  const summaryLine = `${summaryLabel} [FAIL: ${failCount}] | [WARN: ${warnCount}]${issuesOnly ? " (Issues Only)" : ` | [PASS: ${passCount}]`}`;

  const lines = [
    "======================================================================",
    headerTitle,
    "======================================================================",
    `${timestampLabel} ${dateStr}`,
    `${scopeLabel} ${scopeMap[kind] || ("Fortinet Infrastructure")}`,
    summaryLine,
  ];

  if (options.profile === "cis" && typeof options.cisScore === "number") {
    lines.push(
      `CIS Score:    ${options.cisScore}% (${options.totalPassed || 0}/${options.totalEvaluated || 0} controls passed)`
    );
  }

  lines.push("======================================================================");
  lines.push("");

  const fails = activeFindings.filter((f) => f.status === "FAIL");
  if (fails.length > 0) {
    lines.push(`[!] CRITICAL ITEMS REQUIRING IMMEDIATE SOC ACTION (${fails.length}):`);
    lines.push("======================================================================");
    for (const f of fails) {
      const statusTag = "[FAIL]";
      const dev = f.deviceId || f.deviceName || "Primary-FW";
      lines.push(`* ${statusTag} [${dev}] [${f.id}] ${f.component}`);
      lines.push(`  ${"Diagnostic CLI:"} ${f.diagnosticCmd || DIAGNOSTIC_COMMANDS[f.id] || "diagnose sys status"}`);
      lines.push(`  ${"Target Config:"}  ${getFindingTargetConfig(f)}`);
      if (!f.findingText.includes("\n")) {
        lines.push(`  ${"Finding:"} ${f.findingText}`);
      } else {
        lines.push(`  ${"Finding:"}`);
        f.findingText.split("\n").forEach((l) => lines.push(`    ${l}`));
      }
      if (f.actionText) {
        lines.push(`  ${"SOC Action:"} ${f.actionText}`);
      }
      if (f.remediationCli) {
        lines.push(`  ${"Remediation CLI:"}`);
        f.remediationCli.split("\n").forEach((l) => lines.push(`    ${l}`));
      }
      lines.push("");
    }
  }

  const warns = activeFindings.filter((f) => f.status === "WARN");
  if (warns.length > 0) {
    lines.push(`[?] SECURITY WARNINGS & OPERATIONAL RISKS (${warns.length}):`);
    lines.push("======================================================================");
    for (const f of warns) {
      const statusTag = "[WARN]";
      const dev = f.deviceId || f.deviceName || "Primary-FW";
      lines.push(`* ${statusTag} [${dev}] [${f.id}] ${f.component}`);
      lines.push(`  ${"Diagnostic CLI:"} ${f.diagnosticCmd || DIAGNOSTIC_COMMANDS[f.id] || "diagnose sys status"}`);
      lines.push(`  ${"Target Config:"}  ${getFindingTargetConfig(f)}`);
      if (!f.findingText.includes("\n")) {
        lines.push(`  ${"Finding:"} ${f.findingText}`);
      } else {
        lines.push(`  ${"Finding:"}`);
        f.findingText.split("\n").forEach((l) => lines.push(`    ${l}`));
      }
      if (f.actionText) {
        lines.push(`  ${"SOC Action:"} ${f.actionText}`);
      }
      if (f.remediationCli) {
        lines.push(`  ${"Remediation CLI:"}`);
        f.remediationCli.split("\n").forEach((l) => lines.push(`    ${l}`));
      }
      lines.push("");
    }
  }

  if (!issuesOnly) {
    const passes = activeFindings.filter((f) => f.status === "PASS");
    if (passes.length > 0) {
      lines.push(`[+] VERIFIED HEALTHY CONTROLS & PASSING CHECKS (${passes.length}):`);
      lines.push("======================================================================");
      for (const f of passes) {
        const statusTag = "[PASS]";
        const dev = f.deviceId || f.deviceName || "Primary-FW";
        lines.push(`* ${statusTag} [${dev}] [${f.id}] ${f.component}`);
        lines.push(`  ${"Diagnostic CLI:"} ${f.diagnosticCmd || DIAGNOSTIC_COMMANDS[f.id] || "diagnose sys status"}`);
        lines.push(`  ${"Target Config:"}  ${getFindingTargetConfig(f)}`);
        if (!f.findingText.includes("\n")) {
          lines.push(`  ${"Finding:"} ${f.findingText}`);
        } else {
          lines.push(`  ${"Finding:"}`);
          f.findingText.split("\n").forEach((l) => lines.push(`    ${l}`));
        }
      }
      lines.push("");
    }

    const infos = activeFindings.filter((f) => f.status === "INFO");
    if (infos.length > 0) {
      lines.push(`[i] SECOPS OPERATIONAL GUIDANCE:`);
      lines.push("======================================================================");
      for (const f of infos) {
        const statusTag = "[INFO]";
        const dev = f.deviceId || f.deviceName || "Primary-FW";
        lines.push(`* ${statusTag} [${dev}] [${f.id}] ${f.component}`);
        lines.push(`  ${"Diagnostic CLI:"} ${f.diagnosticCmd || DIAGNOSTIC_COMMANDS[f.id] || "diagnose sys status"}`);
        lines.push(`  ${"Target Config:"}  ${getFindingTargetConfig(f)}`);
        if (!f.findingText.includes("\n")) {
          lines.push(`  ${"Finding:"} ${f.findingText}`);
        } else {
          lines.push(`  ${"Finding:"}`);
          f.findingText.split("\n").forEach((l) => lines.push(`    ${l}`));
        }
        if (f.actionText) {
          lines.push(`  ${"Guidance:"} ${f.actionText}`);
        }
      }
      lines.push("");
    }
  }

  lines.push("======================================================================");
  lines.push("Report generated by SecOps Health Check & Config Analyzer");
  lines.push("======================================================================");

  return redactSensitiveData(lines.join("\n"));
}

/**
 * Backwards compatibility alias for generating report text without markdown asterisks.
 */
function generateClickUpReport(findings, kind, options = {}) {
  return generateCleanPlainText(findings, kind, options);
}

/**
 * Generates standalone, beautifully styled executive HTML report.
 * Enterprise SOC-grade typography and structured finding cards.
 * Zero emojis, self-contained responsive CSS with dark/light mode and clean print styles.
 * Supports dual-language and RTL formatting.
 */
function generateStandaloneHtmlDocument(findings, kind, options = {}) {
  const lang = options.lang || "en";
  const issuesOnly = options.issuesOnly || false;
  const isHe = lang === "he";
  const dateStr = new Date().toISOString().replace("T", " ").substring(0, 19) + " UTC";

  let activeFindings = issuesOnly
    ? findings.filter((f) => f.status === "FAIL" || f.status === "WARN")
    : findings;

  if (lang === "he") {
    activeFindings = activeFindings.map((f) => getLocalizedFinding(f, "he"));
  }

  const passCount = activeFindings.filter((f) => f.status === "PASS").length;
  const warnCount = activeFindings.filter((f) => f.status === "WARN").length;
  const failCount = activeFindings.filter((f) => f.status === "FAIL").length;

  const fails = activeFindings.filter((f) => f.status === "FAIL");
  const warns = activeFindings.filter((f) => f.status === "WARN");
  const passes = activeFindings.filter((f) => f.status === "PASS");
  const infos = activeFindings.filter((f) => f.status === "INFO");

  const metadata = extractDeviceMetadata(findings, kind, options.rawText || "");

  const scopeMapEn = {
    fgt: "FortiGate Live CLI Diagnostics",
    faz: "FortiAnalyzer Live CLI Diagnostics",
    dual: "FortiGate + FortiAnalyzer Live Dual Audit",
    conf: "FortiOS Static Configuration Hardening",
    none: "SecOps Security Inspection",
  };
    const scopeMap = scopeMapEn;

  const hasCisScore = options.profile === "cis" && typeof options.cisScore === "number";
  const cisScore = hasCisScore ? options.cisScore : 0;
  const scoreClass = cisScore >= 85 ? "score-high" : cisScore >= 70 ? "score-medium" : "score-low";

  const docTitle = `SecOps Health Check & Security Audit - ${metadata.hostname} (${dateStr})`;

  // Helper to render an executive finding card
  function renderCard(f) {
    const status = f.status.toUpperCase();
    let badgeClass = "badge-pass";
    let statusLabel = "PASS";
    let cardStatusClass = "card-status-pass";

    if (status === "FAIL") {
      badgeClass = "badge-critical";
      statusLabel = "CRITICAL";
      cardStatusClass = "card-status-fail";
    } else if (status === "WARN") {
      badgeClass = "badge-warning";
      statusLabel = "WARNING";
      cardStatusClass = "card-status-warn";
    } else if (status === "INFO") {
      badgeClass = "badge-info";
      statusLabel = "INFO";
      cardStatusClass = "card-status-info";
    }

    const targetConfig = getFindingTargetConfig(f);

    return `
    <div class="finding-card ${cardStatusClass}">
      <div class="card-header">
        <div class="card-title-group">
          <span class="badge ${badgeClass}">${statusLabel}</span>
          <span class="card-rule-title"><strong>[${escapeHtml(f.id)}]</strong> ${escapeHtml(f.component)}</span>
        </div>
        <span class="card-device-badge card-device-pill"><strong>${"Appliance:"}</strong> <code>${escapeHtml(f.deviceId || f.deviceName || "Primary-FW")}</code></span>
        <div class="card-meta-row">
          <span class="meta-item"><strong>${"Diagnostic CLI:"}</strong> <code class="cli-cmd-badge">${escapeHtml(f.diagnosticCmd || DIAGNOSTIC_COMMANDS[f.id] || "diagnose sys status")}</code></span>
          <span class="meta-item"><strong>${"Target Config:"}</strong> <code class="config-path">${escapeHtml(targetConfig)}</code></span>
        </div>
      </div>
      <div class="card-body">
        <div class="section-block observed-state">
          <div class="block-title">${"Observed Configuration State:"}</div>
          <div class="finding-text">${formatFindingHtml(f.findingText)}</div>
        </div>
        ${
          f.actionText
            ? `
        <div class="section-block soc-action">
          <div class="block-title">${"SOC Impact & Action Required:"}</div>
          <div class="action-text">${escapeHtml(f.actionText)}</div>
        </div>`
            : ""
        }
        ${
          f.remediationCli
            ? `
        <div class="section-block remediation-cli card-remediation-cli">
          <div class="remediation-header">
            <span class="remediation-title">${"Remediation CLI Commands:"}</span>
            <button class="copy-cli-btn" type="button" onclick="copyCliBlock(this)">${"Copy CLI"}</button>
          </div>
          <pre class="cli-code"><code>${escapeHtml(f.remediationCli)}</code></pre>
        </div>`
            : ""
        }
      </div>
    </div>`;
  }

  let cardsHtml = "";

  if (fails.length > 0) {
    cardsHtml += `
    <div class="finding-section">
      <div class="section-title section-title-fail">
        <span>${"Critical Items Requiring Immediate SOC Action"}</span>
        <span class="section-count">${fails.length}</span>
      </div>
      ${fails.map(renderCard).join("")}
    </div>`;
  }

  if (warns.length > 0) {
    cardsHtml += `
    <div class="finding-section">
      <div class="section-title section-title-warn">
        <span>${"Security Warnings & Operational Risks"}</span>
        <span class="section-count">${warns.length}</span>
      </div>
      ${warns.map(renderCard).join("")}
    </div>`;
  }

  if (!issuesOnly && passes.length > 0) {
    cardsHtml += `
    <div class="finding-section">
      <div class="section-title section-title-pass">
        <span>${"Verified Healthy Controls & Passing Checks"}</span>
        <span class="section-count">${passes.length}</span>
      </div>
      ${passes.map(renderCard).join("")}
    </div>`;
  }

  if (!issuesOnly && infos.length > 0) {
    cardsHtml += `
    <div class="finding-section">
      <div class="section-title section-title-info">
        <span>${"SecOps Operational Guidance"}</span>
        <span class="section-count">${infos.length}</span>
      </div>
      ${infos.map(renderCard).join("")}
    </div>`;
  }

  const htmlDoc = `<!DOCTYPE html>
<html lang="${lang}" dir="${"ltr"}">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(docTitle)}</title>
  <style>
    :root {
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --border: #e2e8f0;
      --text-primary: #0f172a;
      --text-secondary: #475569;
      --text-muted: #94a3b8;
      --card-shadow: 0 1px 3px rgba(0,0,0,0.06), 0 1px 2px rgba(0,0,0,0.04);
      --code-bg: #0b1118;
      --code-border: #1e293b;
      --code-text: #38bdf8;
      --table-bg: #f8fafc;
      --crit-bg: rgba(239, 68, 68, 0.1);
      --crit-text: #dc2626;
      --crit-border: rgba(239, 68, 68, 0.25);
      --warn-bg: rgba(245, 158, 11, 0.1);
      --warn-text: #d97706;
      --warn-border: rgba(245, 158, 11, 0.25);
      --pass-bg: rgba(16, 185, 129, 0.1);
      --pass-text: #059669;
      --pass-border: rgba(16, 185, 129, 0.25);
      --info-bg: rgba(14, 165, 233, 0.1);
      --info-text: #0284c7;
      --info-border: rgba(14, 165, 233, 0.25);
      --cis-bg: rgba(99, 102, 241, 0.1);
      --cis-text: #4f46e5;
      --cis-border: rgba(99, 102, 241, 0.25);
    }
    @media (prefers-color-scheme: dark) {
      :root {
        --bg: #090d12;
        --card-bg: #111827;
        --border: #1f2937;
        --text-primary: #f9fafb;
        --text-secondary: #9ca3af;
        --text-muted: #6b7280;
        --card-shadow: 0 4px 14px rgba(0,0,0,0.35);
        --code-bg: #030712;
        --code-border: #1f2937;
        --code-text: #38bdf8;
        --table-bg: #1f2937;
        --crit-bg: rgba(239, 68, 68, 0.15);
        --crit-text: #f87171;
        --crit-border: rgba(239, 68, 68, 0.35);
        --warn-bg: rgba(245, 158, 11, 0.15);
        --warn-text: #fbbf24;
        --warn-border: rgba(245, 158, 11, 0.35);
        --pass-bg: rgba(16, 185, 129, 0.15);
        --pass-text: #34d399;
        --pass-border: rgba(16, 185, 129, 0.35);
        --info-bg: rgba(14, 165, 233, 0.15);
        --info-text: #38bdf8;
        --info-border: rgba(14, 165, 233, 0.35);
        --cis-bg: rgba(99, 102, 241, 0.15);
        --cis-text: #a5b4fc;
        --cis-border: rgba(99, 102, 241, 0.35);
      }
    }
    * { box-sizing: border-box; }
    body {
      background-color: var(--bg);
      color: var(--text-primary);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", "Heebo", "Assistant", sans-serif;
      line-height: 1.6;
      margin: 0;
      padding: 36px 20px;
      display: flex;
      justify-content: center;
      ${"direction: ltr; text-align: left;"}
    }
    .report-container {
      max-width: 920px;
      width: 100%;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 36px;
      box-shadow: var(--card-shadow);
    }
    .report-header {
      border-bottom: 2px solid var(--border);
      padding-bottom: 20px;
      margin-bottom: 24px;
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
    }
    .header-eyebrow {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      color: #0284c7;
      letter-spacing: 0.8px;
      margin-bottom: 4px;
    }
    .header-title {
      font-size: 22px;
      font-weight: 800;
      color: var(--text-primary);
      margin: 0 0 6px 0;
    }
    .header-subtitle {
      font-size: 13px;
      color: var(--text-secondary);
    }
    .engine-badge {
      display: inline-block;
      padding: 4px 10px;
      background: var(--table-bg);
      border: 1px solid var(--border);
      border-radius: 4px;
      font-size: 11px;
      font-weight: 600;
      color: var(--text-secondary);
      font-family: monospace;
    }
    .meta-table {
      width: 100%;
      border-collapse: collapse;
      margin-bottom: 24px;
      font-size: 12.5px;
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      overflow: hidden;
    }
    .meta-table th {
      background: var(--table-bg);
      color: var(--text-secondary);
      text-align: ${"left"};
      padding: 8px 12px;
      font-weight: 600;
      border: 1px solid var(--border);
      width: 20%;
    }
    .meta-table td {
      padding: 8px 12px;
      border: 1px solid var(--border);
      color: var(--text-primary);
    }
    .badge-bar {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 12px;
      margin-bottom: 28px;
    }
    .metric-pill {
      padding: 12px 14px;
      border-radius: 6px;
      font-weight: 700;
      font-size: 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .metric-label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .metric-value {
      font-size: 18px;
      font-weight: 800;
    }
    .metric-fail { background: var(--crit-bg); color: var(--crit-text); border: 1px solid var(--crit-border); }
    .metric-warn { background: var(--warn-bg); color: var(--warn-text); border: 1px solid var(--warn-border); }
    .metric-pass { background: var(--pass-bg); color: var(--pass-text); border: 1px solid var(--pass-border); }
    .metric-cis { background: var(--cis-bg); color: var(--cis-text); border: 1px solid var(--cis-border); }

    .score-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-weight: 700;
    }
    .score-high { color: #059669; background: var(--pass-bg); }
    .score-medium { color: #d97706; background: var(--warn-bg); }
    .score-low { color: #dc2626; background: var(--crit-bg); }

    .finding-section {
      margin-bottom: 28px;
    }
    .section-title {
      font-size: 14.5px;
      font-weight: 700;
      margin: 20px 0 12px 0;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .section-title-fail { color: #dc2626; border-bottom-color: rgba(239,68,68,0.25); }
    .section-title-warn { color: #d97706; border-bottom-color: rgba(245,158,11,0.25); }
    .section-title-pass { color: #059669; border-bottom-color: rgba(16,185,129,0.25); }
    .section-title-info { color: #0284c7; border-bottom-color: rgba(14,165,233,0.25); }
    .section-count {
      font-size: 12px;
      padding: 1px 8px;
      border-radius: 9999px;
      background: var(--table-bg);
      border: 1px solid var(--border);
      font-weight: 600;
    }

    .finding-card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      margin-bottom: 14px;
      box-shadow: var(--card-shadow);
      overflow: hidden;
      ${"border-left: 4px solid var(--border);"}
    }
    .card-status-fail { ${"border-left-color: #ef4444;"} }
    .card-status-warn { ${"border-left-color: #f59e0b;"} }
    .card-status-pass { ${"border-left-color: #10b981;"} }
    .card-status-info { ${"border-left-color: #0ea5e9;"} }

    .card-header {
      padding: 10px 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 8px;
      border-bottom: 1px solid var(--border);
      background: var(--table-bg);
    }
    .card-title-group {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .card-rule-title {
      font-size: 13.5px;
      font-weight: 600;
      color: var(--text-primary);
    }
    .card-meta-row {
      display: flex;
      flex-wrap: wrap;
      gap: 6px 12px;
      align-items: center;
      font-family: monospace;
      font-size: 11px;
    }
    .meta-item {
      display: inline-flex;
      align-items: center;
      gap: 4px;
    }
    .meta-item strong {
      color: var(--text-muted);
      font-size: 10.5px;
    }
    .cli-cmd-badge {
      background: var(--table-bg);
      color: #0284c7;
      padding: 2px 6px;
      border-radius: 4px;
      border: 1px solid var(--border);
      font-weight: 600;
      direction: ltr;
    }
    .config-path {
      font-family: monospace;
      font-size: 11px;
      color: var(--text-secondary);
      background: var(--card-bg);
      padding: 2px 6px;
      border-radius: 4px;
      border: 1px solid var(--border);
      direction: ltr;
    }
    .card-device-pill,
    .device-pill {
      font-family: monospace;
      font-size: 11px;
      font-weight: 600;
      color: var(--text-primary);
      background: rgba(14, 165, 233, 0.12);
      border: 1px solid rgba(14, 165, 233, 0.3);
      padding: 2px 7px;
      border-radius: 4px;
      display: inline-flex;
      align-items: center;
      gap: 5px;
      direction: ltr;
    }
    .card-device-pill code,
    .device-pill code {
      color: #0284c7;
      font-weight: 700;
    }
    .finding-bullets {
      margin: 6px 0 6px 18px;
      padding: 0;
      list-style-type: disc;
    }
    [dir="rtl"] .finding-bullets {
      margin: 6px 18px 6px 0;
      padding: 0;
    }
    .finding-bullets li {
      margin-bottom: 4px;
      line-height: 1.5;
    }
    .card-body {
      padding: 14px;
    }
    .section-block {
      margin-bottom: 12px;
    }
    .section-block:last-child {
      margin-bottom: 0;
    }
    .block-title {
      font-size: 10.5px;
      font-weight: 700;
      text-transform: uppercase;
      color: var(--text-muted);
      letter-spacing: 0.5px;
      margin-bottom: 4px;
    }
    .finding-text {
      font-size: 12.5px;
      color: var(--text-primary);
      line-height: 1.6;
      white-space: pre-wrap;
    }
    .soc-action {
      background: rgba(16, 185, 129, 0.05);
      padding: 10px 12px;
      border-radius: 4px;
      ${"border-left: 3px solid #10b981;"}
    }
    .soc-action .block-title {
      color: #059669;
    }
    .action-text {
      font-size: 12px;
      color: var(--text-primary);
      line-height: 1.5;
    }
    .remediation-cli {
      background: var(--code-bg);
      border: 1px solid var(--code-border);
      border-radius: 4px;
      padding: 10px 12px;
      margin-top: 8px;
    }
    .remediation-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 6px;
    }
    .remediation-title {
      font-size: 10.5px;
      font-weight: 700;
      text-transform: uppercase;
      color: var(--text-muted);
      font-family: monospace;
    }
    .copy-cli-btn {
      background: #1e293b;
      color: #38bdf8;
      border: 1px solid #334155;
      padding: 3px 8px;
      font-size: 11px;
      font-weight: 600;
      border-radius: 4px;
      cursor: pointer;
      transition: all 150ms ease;
      font-family: sans-serif;
    }
    .copy-cli-btn:hover {
      background: #334155;
      color: #ffffff;
    }
    .copy-cli-btn.copied {
      background: #10b981 !important;
      color: #ffffff !important;
      border-color: #10b981 !important;
    }
    .cli-code {
      margin: 0;
      font-family: "JetBrains Mono", Consolas, Menlo, monospace;
      font-size: 11.5px;
      color: var(--code-text);
      line-height: 1.5;
      white-space: pre;
      overflow-x: auto;
      direction: ltr;
      text-align: left;
    }

    .badge {
      display: inline-flex;
      align-items: center;
      padding: 2px 7px;
      border-radius: 4px;
      font-size: 10.5px;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      font-family: monospace;
    }
    .badge-critical { background: var(--crit-bg); color: var(--crit-text); border: 1px solid var(--crit-border); }
    .badge-warning { background: var(--warn-bg); color: var(--warn-text); border: 1px solid var(--warn-border); }
    .badge-pass { background: var(--pass-bg); color: var(--pass-text); border: 1px solid var(--pass-border); }
    .badge-info { background: var(--info-bg); color: var(--info-text); border: 1px solid var(--info-border); }

    .report-footer {
      margin-top: 32px;
      padding-top: 14px;
      border-top: 1px solid var(--border);
      font-size: 11px;
      color: var(--text-muted);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    @media print {
      body { background: #fff !important; color: #000 !important; padding: 0 !important; }
      .report-container { max-width: 100% !important; padding: 0 !important; border: none !important; box-shadow: none !important; }
      .copy-cli-btn { display: none !important; }
      .finding-card { break-inside: avoid; page-break-inside: avoid; box-shadow: none !important; border: 1px solid #cbd5e1 !important; margin-bottom: 12px !important; }
      .remediation-cli { background: #f8fafc !important; color: #0f172a !important; border: 1px solid #cbd5e1 !important; }
      .cli-code { color: #0f172a !important; }
    }
  </style>
</head>
<body>
  <div class="report-container">
    <div class="report-header">
      <div>
        <div class="header-eyebrow">${"EXECUTIVE SOC AUDIT DELIVERABLE"}</div>
        <h1 class="header-title">${"SecOps Health Check & Security Audit Report"}</h1>
        <div class="header-subtitle">${"Enterprise Fortinet Infrastructure Assessment & CIS Hardening Benchmark"}</div>
      </div>
      <div>
        <span class="engine-badge">${escapeHtml(metadata.auditorEngine)}</span>
      </div>
    </div>

    <table class="meta-table">
      <tbody>
        <tr>
          <th>${"Device Hostname"}</th>
          <td><strong>${escapeHtml(metadata.hostname)}</strong></td>
          <th>${"Firmware Build"}</th>
          <td>${escapeHtml(metadata.firmware)}</td>
        </tr>
        <tr>
          <th>${"Serial Number"}</th>
          <td><code>${escapeHtml(metadata.serial)}</code></td>
          <th>${"Audit Scope"}</th>
          <td>${escapeHtml(scopeMap[kind] || ("Fortinet Infrastructure"))}</td>
        </tr>
        <tr>
          <th>${"Audit Timestamp"}</th>
          <td>${escapeHtml(metadata.auditTimestamp)}</td>
          <th>${"Compliance Score"}</th>
          <td><span class="score-badge ${scoreClass}">${hasCisScore ? `${options.cisScore}% (${options.totalPassed || 0}/${options.totalEvaluated || 0})` : "N/A"}</span></td>
        </tr>
      </tbody>
    </table>

    <div class="badge-bar">
      <div class="metric-pill metric-fail">
        <span class="metric-label">${"Critical / Failed"}</span>
        <span class="metric-value">${failCount}</span>
      </div>
      <div class="metric-pill metric-warn">
        <span class="metric-label">${"Warnings"}</span>
        <span class="metric-value">${warnCount}</span>
      </div>
      ${issuesOnly ? "" : `
      <div class="metric-pill metric-pass">
        <span class="metric-label">${"Passing Checks"}</span>
        <span class="metric-value">${passCount}</span>
      </div>`}
      ${hasCisScore ? `
      <div class="metric-pill metric-cis">
        <span class="metric-label">${"CIS Score"}</span>
        <span class="metric-value">${options.cisScore}%</span>
      </div>` : ""}
    </div>

    ${cardsHtml}

    <div class="report-footer">
      <span>${"Generated by SecOps Health Check &amp; Config Analyzer"}</span>
      <span>${escapeHtml(metadata.auditTimestamp)}</span>
    </div>
  </div>

  <script>
    function copyCliBlock(btn) {
      var card = btn.closest('.card-remediation-cli');
      if (!card) return;
      var code = card.querySelector('code');
      if (!code) return;
      var text = code.innerText || code.textContent;
      navigator.clipboard.writeText(text).then(function() {
        var orig = btn.innerText;
        btn.innerText = "${"Copied!"}";
        btn.classList.add("copied");
        setTimeout(function() {
          btn.innerText = orig;
          btn.classList.remove("copied");
        }, 2000);
      }).catch(function() {
        var ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        var orig = btn.innerText;
        btn.innerText = "${"Copied!"}";
        setTimeout(function() { btn.innerText = orig; }, 2000);
      });
    }
  </script>
</body>
</html>`;
  return redactSensitiveData(htmlDoc);
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 200);
}

// =====================================================================
// Verified SecOps CLI Cheat Sheet Bundles
// =====================================================================
const CHEAT_SHEET_GROUPS = [
  {
    id: "fgt",
    label: "FortiGate Live Health Check Block",
    bundle: [
      "config system console",
      "    set output standard",
      "end",
      "get system status",
      "get system performance status",
      "diagnose hardware sysinfo conserve",
      "diagnose sys session stat",
      "get router info bgp summary",
      "get router info ospf neighbor",
      "get system ha status",
      "get system global",
      "get system global | grep -i strong-crypto",
      "get system global | grep -i ssl-min",
      "get system ntp",
      "diagnose autoupdate status",
      "get vpn ipsec tunnel summary",
      "get vpn ipsec tunnel details",
      "diagnose vpn ike gateway list",
      "diagnose vpn tunnel list",
      "diagnose sys sdwan health-check",
      "get system external-resource",
      "get system interface physical",
      "diagnose netlink interface list",
      "get vpn certificate local details",
      "show system interface | grep -i allowaccess",
      "show user local",
      "diagnose user ban list",
      "diagnose test application miglogd 6",
      "diagnose debug crashlog read",
      "config system console",
      "    set output more",
      "end",
    ].join("\n"),
    items: [
      { cmd: "get system status", desc: "Uptime (FGT-SYS-01), firmware build, and licensing" },
      { cmd: "get system performance status", desc: "Performance with CPU & RAM utilization (FGT-PERF-01)" },
      { cmd: "diagnose hardware sysinfo conserve", desc: "Kernel memory conserve mode state and threshold headroom (FGT-MEM-02)" },
      { cmd: "diagnose sys session stat", desc: "Session table count, memory tension drops, and ephemeral port usage (FGT-SESS-01)" },
      { cmd: "get router info bgp summary", desc: "BGP neighbor peering states and prefix counts (FGT-RT-BGP-01)" },
      { cmd: "get router info ospf neighbor", desc: "OSPF neighbor adjacencies and state machine audit (FGT-RT-OSPF-01)" },
      { cmd: "get system ha status", desc: "HA Clustering health and cluster sync (FGT-HA-01)" },
      { cmd: "get system global", desc: "Verify active admin timeout and lockout policy (CIS-ADM-01/02)" },
      { cmd: "get system global | grep -i strong-crypto", desc: "Verify strong crypto runtime configuration (CIS-TLS-01)" },
      { cmd: "get system global | grep -i ssl-min", desc: "Verify minimum TLS protocol version runtime configuration (CIS-TLS-01)" },
      { cmd: "get system ntp", desc: "Inspect live NTP daemon synchronization status and server reachability (CIS-SYS-02)" },
      { cmd: "diagnose autoupdate status", desc: "FortiGuard Sync connection and signature freshness (FGT-FG-01)" },
      { cmd: "get vpn ipsec tunnel summary", desc: "IPSec Tunnels selector status line-by-line (FGT-IPSEC-01)" },
      { cmd: "get vpn ipsec tunnel details", desc: "View detailed IPsec tunnel statistics including Rx/Tx data volume (KB) and up-time" },
      { cmd: "diagnose vpn ike gateway list", desc: "Detailed Phase 1 IKE peer status, active negotiations, and authentications" },
      { cmd: "diagnose vpn tunnel list", desc: "Detailed Phase 2 SA status, SPIs, and exact local/remote subnet selectors (FGT-IPSEC-01)" },
      { cmd: "diagnose sys sdwan health-check", desc: "SD-WAN SLA member alive/dead, loss %, latency (FGT-SDWAN-01)" },
      { cmd: "get system external-resource", desc: "Threat Feeds active status and synchronization (FGT-FEED-01)" },
      { cmd: "get system interface physical", desc: "Physical interface link status, speed, and duplex settings (FGT-NET-01)" },
      { cmd: "diagnose netlink interface list", desc: "Physical interface error rates, drops, and collision statistics (FGT-NET-02)" },
      { cmd: "get vpn certificate local details", desc: "Local SSL/VPN certificate validity and expiration dates (FGT-CERT-01)" },
      { cmd: "show system interface | grep -i allowaccess", desc: "WAN Interface Access external exposure audit (SEC-INTF-01)" },
      { cmd: "show user local", desc: "Local User MFA verification on password accounts (SEC-USER-01)" },
      { cmd: "diagnose user ban list", desc: "Banned IPs in quarantine ban table (FGT-BAN-01)" },
      { cmd: "diagnose test application miglogd 6", desc: "Log Delivery transmission counter to FAZ (FGT-LOG-01)" },
      { cmd: "diagnose debug crashlog read", desc: "Daemon crashlog buffer history and signal analysis (FGT-SYS-03)" },
    ],
  },
  {
    id: "faz",
    label: "FortiAnalyzer Live Health Check Block",
    bundle: [
      "get system status",
      "get system performance",
      "get system ha",
      "diagnose system print df",
      "diagnose log device",
      "diagnose test application oftpd 3",
      "diagnose fortilogd msgrate",
      "diagnose test application sqlplugind 2",
    ].join("\n"),
    items: [
      { cmd: "get system status", desc: "FAZ license validity, system status, and HA mode (FAZ-SYS-01)" },
      { cmd: "get system performance", desc: "CPU and memory utilization excluding swap (FAZ-SYS-01)" },
      { cmd: "get system ha", desc: "FortiAnalyzer HA cluster configuration and status (FAZ-SYS-01)" },
      { cmd: "diagnose system print df", desc: "Storage Threshold /Storage and /var partitions (FAZ-STOR-01)" },
      { cmd: "diagnose log device", desc: "System storage summary and device log quotas (FAZ-STOR-01)" },
      { cmd: "diagnose test application oftpd 3", desc: "Active connected firewall sessions and idle times (FAZ-CONN-01)" },
      { cmd: "diagnose fortilogd msgrate", desc: "Log ingestion message rate over last 60 seconds (FAZ-IDX-01)" },
      { cmd: "diagnose test application sqlplugind 2", desc: "SQL log insert speed and disk I/O utilization stats (FAZ-IDX-01)" },
    ],
  },
];

// =====================================================================
// DOM Elements & UI State Management
// =====================================================================
const DOM = {
  detectBadge: document.getElementById("detectBadge"),
  timestampBadge: document.getElementById("timestampBadge"),
  pillCisScore: document.getElementById("pillCisScore"),
  countCisScore: document.getElementById("countCisScore"),
  labelCisScore: document.getElementById("labelCisScore"),
  countPass: document.getElementById("countPass"),
  countWarn: document.getElementById("countWarn"),
  countFail: document.getElementById("countFail"),
  dropZone: document.getElementById("dropZone"),
  fileInput: document.getElementById("fileInput"),
  dropzonePrompt: document.getElementById("dropzonePrompt"),
  fileListContainer: document.getElementById("fileListContainer"),
  fileListCount: document.getElementById("fileListCount"),
  fileChipsWrapper: document.getElementById("fileChipsWrapper"),
  clearAllFilesBtn: document.getElementById("clearAllFilesBtn"),
  pasteToggleBtn: document.getElementById("pasteToggleBtn"),
  pasteBody: document.getElementById("pasteBody"),
  charCounter: document.getElementById("charCounter"),
  cliInput: document.getElementById("cliInput"),
  analyzeBtn: document.getElementById("analyzeBtn"),
  clearBtn: document.getElementById("clearBtn"),
  copyRichTextBtn: document.getElementById("copyRichTextBtn"),
  copyPlainTextBtn: document.getElementById("copyPlainTextBtn"),
  downloadHtmlBtn: document.getElementById("downloadHtmlBtn"),
  downloadTxtBtn: document.getElementById("downloadTxtBtn"),
  findingsCountBadge: document.getElementById("findingsCountBadge"),
  resultsBody: document.getElementById("resultsBody"),
  toast: document.getElementById("toast"),
  tabBtnAnalyzer: document.getElementById("tabBtnAnalyzer"),
  tabBtnCheatsheet: document.getElementById("tabBtnCheatsheet"),
  viewAnalyzer: document.getElementById("viewAnalyzer"),
  viewCheatsheet: document.getElementById("viewCheatsheet"),
  cheatsheetGroups: document.getElementById("cheatsheetGroups"),
  filterIssuesOnly: document.getElementById("filterIssuesOnly"),
  filterIssuesText: document.getElementById("filterIssuesText"),
  resultsHeading: document.getElementById("resultsHeading"),
  thCheckId: document.getElementById("thCheckId"),
  thComponent: document.getElementById("thComponent"),
  thStatus: document.getElementById("thStatus"),
  thFindings: document.getElementById("thFindings"),
  tabLabelAnalyzer: document.getElementById("tabLabelAnalyzer"),
  tabLabelCheatsheet: document.getElementById("tabLabelCheatsheet"),
  labelPass: document.getElementById("labelPass"),
  labelWarn: document.getElementById("labelWarn"),
  labelFail: document.getElementById("labelFail"),
  dropzonePrimary: document.getElementById("dropzonePrimary"),
  dropzoneSub: document.getElementById("dropzoneSub"),
  pasteToggleText: document.getElementById("pasteToggleText"),
  analyzeBtnText: document.getElementById("analyzeBtnText"),
  clearBtnText: document.getElementById("clearBtnText"),
  btnTextRich: document.getElementById("btnTextRich"),
  btnTextPlain: document.getElementById("btnTextPlain"),
  btnTextHtml: document.getElementById("btnTextHtml"),
  btnTextTxt: document.getElementById("btnTextTxt"),
  cheatsheetTitle: document.getElementById("cheatsheetTitle"),
  cheatsheetDesc: document.getElementById("cheatsheetDesc"),
  tabBtnHtml: document.getElementById("tab-btn-html"),
  tabBtnPlain: document.getElementById("tab-btn-plain"),
  viewHtml: document.getElementById("view-html"),
  viewPlain: document.getElementById("view-plain"),
  btnCopyClickup: document.getElementById("btn-copy-clickup"),
  plainTextOutput: document.getElementById("plainTextOutput"),
  summaryCountText: document.getElementById("summaryCountText"),
  browseBtn: document.getElementById("browseBtn"),
  verifiedText: document.getElementById("verifiedText"),
};

let currentFindings = [];
let loadedFiles = []; // Array of { id, name, size, type, content }
let currentLang = "en";
let issuesOnly = false;
try {
  const savedLang = localStorage.getItem("secops_lang");
  if (savedLang === "en") currentLang = savedLang;
} catch (e) {}
try {
  issuesOnly = localStorage.getItem("secops_issues_only") === "true";
} catch (e) {}

function showToast(m) {
  if (!DOM.toast) return;
  DOM.toast.textContent = m;
  DOM.toast.classList.add("show");
  setTimeout(() => DOM.toast.classList.remove("show"), 2200);
}

function updateTimestamp() {
  if (DOM.timestampBadge) {
    DOM.timestampBadge.textContent = new Date().toLocaleTimeString([], { hour12: false });
  }
}

function updateDetectBadge(kind) {
  if (!DOM.detectBadge) return;
  const s = UI_STRINGS[currentLang] || UI_STRINGS.en;
  DOM.detectBadge.textContent = (s.detectBadge && (s.detectBadge[kind] || s.detectBadge.none)) || kind;
  DOM.detectBadge.dataset.kind = kind;
}

function updateCharCounter() {
  if (DOM.charCounter && DOM.cliInput) {
    DOM.charCounter.textContent = `${(DOM.cliInput.value || "").length.toLocaleString()} chars`;
  }
}

function updateSummaryIndicator(files, checks) {
  if (DOM.summaryCountText) {
    DOM.summaryCountText.textContent = `${files} file${files === 1 ? "" : "s"} parsed · ${checks} checks evaluated`;
  }
}

async function computeSha256(str) {
  if (!str) return "";
  try {
    if (typeof crypto !== "undefined" && crypto.subtle && typeof TextEncoder !== "undefined") {
      const enc = new TextEncoder();
      const hashBuffer = await crypto.subtle.digest("SHA-256", enc.encode(str));
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    }
  } catch (err) {
    console.warn("SHA-256 calculation error:", err);
  }
  return "";
}

async function updateVerifiedHash(content) {
  if (!DOM.verifiedText) return;
  if (!content || !content.trim()) {
    DOM.verifiedText.textContent = "Local Client-Side Only";
    DOM.verifiedText.title = "All configuration and CLI telemetry is parsed strictly within your local browser sandbox. Zero data exfiltration.";
    return;
  }
  const hash = await computeSha256(content);
  if (hash) {
    DOM.verifiedText.textContent = `SHA-256: ${hash.slice(0, 8)}...`;
    DOM.verifiedText.title = `SHA-256 Checksum: ${hash} (Local Browser Validation)`;
  } else {
    DOM.verifiedText.textContent = "Verified Local Parse";
    DOM.verifiedText.title = "Parsed locally in client sandbox.";
  }
}

function checkIssuesExportAllowed() {
  const isOnly = DOM.filterIssuesOnly ? DOM.filterIssuesOnly.checked : false;
  const profileFindings = currentFindings;
  if (isOnly) {
    const issues = profileFindings.filter((f) => f.status === "FAIL" || f.status === "WARN");
    if (issues.length === 0) {
      showToast(UI_STRINGS[currentLang].toastNoIssues || ("All checks passed! No issues to copy."));
      return false;
    }
  }
  return true;
}

function getExportPayload() {
  const profileFindings = currentFindings;

  const cisPassed = currentFindings.filter((f) => CIS_BENCHMARK_CONTROL_IDS.includes(f.id) && f.status === "PASS").length;
  const totalPassed = cisPassed;
  const totalEvaluated = CIS_BENCHMARK_TOTAL_CONTROLS;
  const cisScore = Math.round((cisPassed / CIS_BENCHMARK_TOTAL_CONTROLS) * 100);

  const isOnly = DOM.filterIssuesOnly ? DOM.filterIssuesOnly.checked : false;
  let rawText = DOM.cliInput ? DOM.cliInput.value || "" : "";
  if (!rawText.trim() && loadedFiles.length > 0) {
    rawText = loadedFiles.map((f) => f.content).join("\n\n");
  }
  const kind = detectInputKind(rawText);
  const opts = {
    lang: currentLang,
    issuesOnly: isOnly,
    profile: "full",
    cisScore,
    totalPassed,
    totalEvaluated,
    rawText,
  };

  return { findings: profileFindings, kind, opts };
}

function switchWorkspaceView(view) {
  const isHtml = view === "html";
  DOM.viewHtml.classList.toggle("is-hidden", !isHtml);
  DOM.viewPlain.classList.toggle("is-hidden", isHtml);
  DOM.tabBtnHtml.classList.toggle("is-active", isHtml);
  DOM.tabBtnPlain.classList.toggle("is-active", !isHtml);
  DOM.tabBtnHtml.setAttribute("aria-selected", String(isHtml));
  DOM.tabBtnPlain.setAttribute("aria-selected", String(!isHtml));

  if (!isHtml && DOM.plainTextOutput && currentFindings.length > 0) {
    const { findings, kind, opts } = getExportPayload();
    DOM.plainTextOutput.textContent = generateCleanPlainText(findings, kind, opts);
  }
}

function updateSummaryCounters(findings) {
  const profileFindings = findings;

  const pass = profileFindings.filter((f) => f.status === "PASS").length;
  const warn = profileFindings.filter((f) => f.status === "WARN").length;
  const fail = profileFindings.filter((f) => f.status === "FAIL").length;

  DOM.countPass.textContent = String(pass);
  DOM.countWarn.textContent = String(warn);
  DOM.countFail.textContent = String(fail);

  // CIS Hardening Score in Full Audit Mode
  const summaryBarEl = document.querySelector(".summary-bar");
  if (profileFindings.length > 0) {
    if (DOM.pillCisScore) {
      DOM.pillCisScore.classList.remove("is-hidden");
      if (summaryBarEl) summaryBarEl.classList.add("has-cis");

      const passedCount = profileFindings.filter((f) => CIS_BENCHMARK_CONTROL_IDS.includes(f.id) && f.status === "PASS").length;
      const cisScore = Math.round((passedCount / CIS_BENCHMARK_TOTAL_CONTROLS) * 100);

      DOM.countCisScore.textContent = `${cisScore}%`;

      DOM.pillCisScore.classList.remove("score-high", "score-mid", "score-low");
      if (cisScore >= 85) DOM.pillCisScore.classList.add("score-high");
      else if (cisScore >= 70) DOM.pillCisScore.classList.add("score-mid");
      else DOM.pillCisScore.classList.add("score-low");
    }
  } else {
    if (DOM.pillCisScore) DOM.pillCisScore.classList.add("is-hidden");
    if (summaryBarEl) summaryBarEl.classList.remove("has-cis");
  }

  const isFiltered = DOM.filterIssuesOnly ? DOM.filterIssuesOnly.checked : false;
  const totalIssues = warn + fail;
  DOM.findingsCountBadge.textContent = isFiltered
      ? `${totalIssues} issue${totalIssues === 1 ? "" : "s"} shown`
      : `${profileFindings.length} item${profileFindings.length === 1 ? "" : "s"}`;

  const filesCount = loadedFiles.length || (DOM.cliInput && DOM.cliInput.value.trim() ? 1 : 0);
  updateSummaryIndicator(filesCount, profileFindings.length);
}

function setExportButtonsEnabled(enabled) {
  DOM.copyRichTextBtn.disabled = !enabled;
  DOM.copyPlainTextBtn.disabled = !enabled;
  DOM.downloadHtmlBtn.disabled = !enabled;
  DOM.downloadTxtBtn.disabled = !enabled;
}

function setLanguage(lang = "en") {
  currentLang = lang || "en";
  try {
    localStorage.setItem("secops_lang", currentLang);
  } catch (e) {}

  if (DOM.langEnBtn && DOM.langHeBtn) {
    DOM.langEnBtn.classList.toggle("is-active", currentLang === "en");
    DOM.langHeBtn.classList.toggle("is-active", false);
  }

  const appEl = document.querySelector(".app") || document.body;
  appEl.classList.remove("is-rtl");
  document.documentElement.setAttribute("dir", "ltr");

  const s = UI_STRINGS[currentLang] || UI_STRINGS.en;
  if (DOM.tabLabelAnalyzer) DOM.tabLabelAnalyzer.textContent = s.tabAnalyzer;
  if (DOM.tabLabelCheatsheet) DOM.tabLabelCheatsheet.textContent = s.tabCheatsheet;
  if (DOM.labelPass) DOM.labelPass.textContent = s.labelPass;
  if (DOM.labelWarn) DOM.labelWarn.textContent = s.labelWarn;
  if (DOM.labelFail) DOM.labelFail.textContent = s.labelFail;
  if (DOM.dropzonePrimary) DOM.dropzonePrimary.innerHTML = s.dropzonePrimary;
  if (DOM.dropzoneSub) DOM.dropzoneSub.textContent = s.dropzoneSub;
  if (DOM.pasteToggleText) DOM.pasteToggleText.textContent = s.pasteToggle;
  if (DOM.analyzeBtnText) DOM.analyzeBtnText.textContent = s.analyzeBtn;
  if (DOM.clearBtnText) DOM.clearBtnText.textContent = s.clearBtn;
  if (DOM.resultsHeading) DOM.resultsHeading.textContent = s.resultsHeading;
  if (DOM.filterIssuesText) DOM.filterIssuesText.textContent = s.filterIssues;
  if (DOM.btnTextRich) DOM.btnTextRich.textContent = s.btnRich;
  if (DOM.btnTextPlain) DOM.btnTextPlain.textContent = s.btnPlain;
  if (DOM.thCheckId) DOM.thCheckId.textContent = s.thCheckId;
  if (DOM.thComponent) DOM.thComponent.textContent = s.thComponent;
  if (DOM.thStatus) DOM.thStatus.textContent = s.thStatus;
  if (DOM.thFindings) DOM.thFindings.textContent = s.thFindings;
  if (DOM.cheatsheetTitle) DOM.cheatsheetTitle.textContent = s.cheatsheetTitle;
  if (DOM.cheatsheetDesc) DOM.cheatsheetDesc.innerHTML = s.cheatsheetDesc;
  if (DOM.labelCisScore) DOM.labelCisScore.textContent = s.labelCisScore;
  if (DOM.tabBtnHtml) DOM.tabBtnHtml.textContent = "HTML Report";
  if (DOM.tabBtnPlain) DOM.tabBtnPlain.textContent = "Plain Text";

  const rawText = DOM.cliInput ? DOM.cliInput.value || "" : "";
  const kind = detectInputKind(rawText);
  updateDetectBadge(kind);
  renderFindings(currentFindings);
  updateSummaryCounters(currentFindings);
  renderCheatsheet();
}

function renderFindings(findings) {
  DOM.resultsBody.innerHTML = "";
  const isFiltered = DOM.filterIssuesOnly ? DOM.filterIssuesOnly.checked : false;
  const profileFindings = findings;

  const displayFindings = isFiltered
    ? profileFindings.filter((f) => f.status === "FAIL" || f.status === "WARN")
    : profileFindings;

  const s = UI_STRINGS[currentLang] || UI_STRINGS.en;

  if (!findings.length) {
    const tr = document.createElement("tr");
    tr.className = "empty-row";
    tr.innerHTML = `
      <td colspan="4">
        <div class="empty-state">
          <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
          <p class="empty-title">${s.emptyTitle}</p>
          <p class="empty-desc">${s.emptyDesc}</p>
        </div>
      </td>
    `;
    DOM.resultsBody.appendChild(tr);
    return;
  }

  if (isFiltered && !displayFindings.length) {
    const tr = document.createElement("tr");
    tr.className = "empty-row";
    tr.innerHTML = `
      <td colspan="4">
        <div class="empty-state">
          <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="#10b981" stroke-width="1.5">
            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p class="empty-title" style="color: #34d399;">${"All Checks Passed Cleanly!"}</p>
          <p class="empty-desc">${"No warnings or critical failures detected across analyzed inputs."}</p>
        </div>
      </td>
    `;
    DOM.resultsBody.appendChild(tr);
    return;
  }

  let deltaBanner = document.querySelector(".delta-backup-banner");
  const isDelta = findings.some((f) => f.source === "conf" || (f.data && f.data.isFactoryDefault));

  if (isDelta && findings.length > 0) {
    if (!deltaBanner) {
      deltaBanner = document.createElement("div");
      deltaBanner.className = "delta-backup-banner";
      const tableWrapper = DOM.resultsBody.closest(".table-container") || DOM.resultsBody.closest("table");
      if (tableWrapper && tableWrapper.parentNode) {
        tableWrapper.parentNode.insertBefore(deltaBanner, tableWrapper);
      }
    }
    deltaBanner.innerHTML = `
      <svg class="delta-backup-banner-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="12" y1="16" x2="12" y2="12"></line>
        <line x1="12" y1="8" x2="12.01" y2="8"></line>
      </svg>
      <div>
        <strong>${"Static Configuration Backup Detected (Delta Configuration):"}</strong>
        ${" Standard FortiOS backups omit factory default values. Compliant defaults (e.g. admin timeout, NTP sync) are evaluated according to vendor baseline standards."}
      </div>
    `;
    deltaBanner.style.display = "flex";
  } else if (deltaBanner) {
    deltaBanner.style.display = "none";
  }

  const distinctDevices = [...new Set(displayFindings.map((f) => f.deviceId || "default"))].filter((d) => d !== "default");
  const hasMultipleDevices = distinctDevices.length > 1;
  let currentDevice = null;

  for (const rawF of displayFindings) {
    const f = getLocalizedFinding(rawF, currentLang);
    const devId = rawF.deviceId || "default";

    if (hasMultipleDevices && devId !== currentDevice) {
      currentDevice = devId;
      const groupTr = document.createElement("tr");
      groupTr.className = "device-group-row";
      groupTr.innerHTML = `
        <td colspan="4">
          <div class="device-group-header">
            <svg style="width: 14px; height: 14px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
              <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
              <line x1="6" y1="6" x2="6.01" y2="6"></line>
              <line x1="6" y1="18" x2="6.01" y2="18"></line>
            </svg>
            <span>${"Device / Asset:"} ${escapeHtml(devId)}</span>
          </div>
        </td>
      `;
      DOM.resultsBody.appendChild(groupTr);
    }

    const tr = document.createElement("tr");

    // Check ID
    const tdId = document.createElement("td");
    tdId.className = "cell-id";
    const idSpan = document.createElement("div");
    idSpan.className = "finding-id-label";
    idSpan.textContent = f.id;
    tdId.appendChild(idSpan);

    const devBadge = document.createElement("span");
    devBadge.className = "device-tag";
    devBadge.textContent = f.deviceId || f.deviceName || (devId !== "default" ? devId : "Primary-FW");
    tdId.appendChild(devBadge);

    // Component
    const tdComp = document.createElement("td");
    tdComp.className = "cell-comp";
    tdComp.textContent = f.component;

    // Status Badge
    const tdStatus = document.createElement("td");
    tdStatus.className = "cell-status";
    const badge = document.createElement("span");
    badge.className = `status-badge ${f.status}`;
    badge.textContent = f.statusLabel || f.status;
    tdStatus.appendChild(badge);

    // Findings & SOC Action
    const tdFindings = document.createElement("td");
    tdFindings.className = "cell-findings";

    const findingSpan = document.createElement("div");
    findingSpan.className = "finding-text";
    findingSpan.innerHTML = formatFindingHtml(f.findingText);
    tdFindings.appendChild(findingSpan);

    const metaRow = document.createElement("div");
    metaRow.className = "card-meta-row";
    const diagCmd = f.diagnosticCmd || DIAGNOSTIC_COMMANDS[f.id] || "diagnose sys status";
    const cfgPath = f.targetConfig || getFindingTargetConfig(f);
    metaRow.innerHTML = `
      <span class="meta-item"><strong>${"Diagnostic CLI:"}</strong> <code class="cli-cmd-badge">${escapeHtml(diagCmd)}</code></span>
      <span class="meta-item"><strong>${"Target Config:"}</strong> <code class="config-path">${escapeHtml(cfgPath)}</code></span>
    `;
    tdFindings.appendChild(metaRow);

    if (f.actionText) {
      const actionBox = document.createElement("div");
      actionBox.className = "soc-action soc-action-card";
      actionBox.innerHTML = `
        <span class="action-prefix">${s.actionPrefix}</span>
        <span class="action-content">${escapeHtml(f.actionText)}</span>
      `;
      tdFindings.appendChild(actionBox);
    }

    if (f.remediationCli) {
      const remBlock = document.createElement("div");
      remBlock.className = "remediation-cli-block";
      remBlock.innerHTML = `
        <div class="remediation-cli-header">
          <span class="remediation-cli-label">${s.remediationLabel || "Remediation CLI:"}</span>
          <button type="button" class="btn-copy-cli" title="Copy CLI Commands">
            <svg class="btn-icon" viewBox="0 0 20 20" fill="currentColor">
              <path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z" />
              <path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 2H9a3 3 0 01-3-2z" />
            </svg>
            <span>${s.btnCopyCli || "Copy CLI"}</span>
          </button>
        </div>
        <pre class="remediation-cli-code"><code>${escapeHtml(f.remediationCli)}</code></pre>
      `;
      const copyBtn = remBlock.querySelector(".btn-copy-cli");
      copyBtn.addEventListener("click", async (ev) => {
        ev.stopPropagation();
        try {
          await navigator.clipboard.writeText(f.remediationCli);
          showToast(s.toastCopiedCli || "Remediation CLI copied to clipboard!");
        } catch (err) {
          showToast("Copy failed");
        }
      });
      tdFindings.appendChild(remBlock);
    }

    tr.appendChild(tdId);
    tr.appendChild(tdComp);
    tr.appendChild(tdStatus);
    tr.appendChild(tdFindings);

    DOM.resultsBody.appendChild(tr);
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

// ---------------------------------------------------------------------
// Multi-File Ingestion & Rendering
// ---------------------------------------------------------------------
function renderFileChips() {
  DOM.fileChipsWrapper.innerHTML = "";

  if (loadedFiles.length === 0) {
    DOM.fileListContainer.classList.add("is-hidden");
    return;
  }

  DOM.fileListContainer.classList.remove("is-hidden");
  DOM.fileListCount.textContent = `Loaded Files (${loadedFiles.length})`;

  for (const file of loadedFiles) {
    const chip = document.createElement("div");
    const isConf = file.name.toLowerCase().endsWith(".conf") || file.name.toLowerCase().endsWith(".cfg");
    chip.className = `file-chip ${isConf ? "is-conf" : "is-cli"}`;

    const sizeKb = (file.size / 1024).toFixed(1);
    const typeLabel = isConf
      ? ("Config")
      : ("CLI Log");

    chip.innerHTML = `
      <svg class="file-chip-icon" viewBox="0 0 20 20" fill="currentColor">
        <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h4.586A2 2 0 0112 2.586L15.414 6A2 2 0 0116 7.414V16a2 2 0 01-2 2H6a2 2 0 01-2-2V4z" clip-rule="evenodd" />
      </svg>
      <span class="file-chip-name" title="${escapeHtml(file.name)}">${escapeHtml(file.name)}</span>
      <span class="file-chip-meta">${sizeKb} KB &bull; ${typeLabel}</span>
      <button type="button" class="file-chip-remove" title="Remove file" aria-label="Remove ${escapeHtml(file.name)}">&times;</button>
    `;

    chip.querySelector(".file-chip-remove").addEventListener("click", (e) => {
      e.stopPropagation();
      removeFileById(file.id);
    });

    DOM.fileChipsWrapper.appendChild(chip);
  }
}

function removeFileById(fileId) {
  loadedFiles = loadedFiles.filter((f) => f.id !== fileId);
  renderFileChips();
  syncAggregatedInput();
  showToast("File removed");
}

function syncAggregatedInput() {
  const parts = loadedFiles.map((f) => f.content);
  const aggregated = parts.join("\n\n");
  DOM.cliInput.value = aggregated;
  updateCharCounter();
  updateDetectBadge(detectInputKind(aggregated));
  updateVerifiedHash(aggregated);
}

async function handleFiles(fileList) {
  if (!fileList || !fileList.length) return;

  const validExtensions = [".txt", ".log", ".conf", ".cfg"];
  const newFiles = [];

  for (let i = 0; i < fileList.length; i++) {
    const file = fileList[i];
    const lower = file.name.toLowerCase();
    const isValid = validExtensions.some((ext) => lower.endsWith(ext));

    if (isValid) {
      newFiles.push(file);
    }
  }

  if (newFiles.length === 0) {
    showToast("Unsupported file(s). Please drop .txt, .log, .conf, or .cfg");
    return;
  }

  const readPromises = newFiles.map((file) => {
    return new Promise((resolve) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        resolve({
          id: `${file.name}_${Date.now()}_${Math.random()}`,
          name: file.name,
          size: file.size,
          type: file.name.toLowerCase().endsWith(".conf") || file.name.toLowerCase().endsWith(".cfg") ? "conf" : "cli",
          content: e.target.result || "",
        });
      };
      reader.onerror = () => resolve(null);
      reader.readAsText(file);
    });
  });

  const results = await Promise.all(readPromises);
  const validResults = results.filter(Boolean);

  loadedFiles = [...loadedFiles, ...validResults];
  renderFileChips();
  syncAggregatedInput();

  showToast(`Loaded ${validResults.length} file(s)`);
}

function clearAllFiles() {
  loadedFiles = [];
  DOM.fileInput.value = "";
  renderFileChips();
  DOM.cliInput.value = "";
  updateCharCounter();
  updateDetectBadge("none");
}

// ---------------------------------------------------------------------
// Cheatsheet View Rendering
// ---------------------------------------------------------------------

function renderCheatsheet() {
  DOM.cheatsheetGroups.innerHTML = "";
  const isHe = currentLang === "he";

  for (const group of CHEAT_SHEET_GROUPS) {
    const groupEl = document.createElement("div");
    groupEl.className = "cheatsheet-group";

    const header = document.createElement("div");
    header.className = "cheatsheet-group-header";

    const title = document.createElement("div");
    title.className = "cheatsheet-group-title";
    const dot = document.createElement("span");
    dot.className = `cheatsheet-group-dot ${group.id}`;
    title.appendChild(dot);

    const groupLabel = group.label;
    title.appendChild(document.createTextNode(groupLabel));

    const copyAllBtn = document.createElement("button");
    copyAllBtn.className = "btn-bundle-copy";
    copyAllBtn.type = "button";
    copyAllBtn.innerHTML = `
      <svg class="btn-icon" viewBox="0 0 20 20" fill="currentColor">
        <path d="M8 3a1 1 0 011-1h2a1 1 0 110 2H9a1 1 0 01-1-1z" />
        <path d="M6 3a2 2 0 00-2 2v11a2 2 0 002 2h8a2 2 0 002-2V5a2 2 0 00-2-2 3 3 0 01-3 2H9a3 3 0 01-3-2z" />
      </svg>
      ${"Copy Verified 1-Click Bundle"}
    `;

    copyAllBtn.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      try {
        await navigator.clipboard.writeText(group.bundle);
        showToast(`1-Click ${group.label} copied!`);
      } catch (err) {
        showToast("Clipboard copy failed");
      }
    });

    header.appendChild(title);
    header.appendChild(copyAllBtn);

    const list = document.createElement("ul");
    list.className = "cheatsheet-list";

    for (const item of group.items) {
      const li = document.createElement("li");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "cheatsheet-item";

      const itemDesc = item.desc;

      btn.innerHTML = `
        <div>
          <span class="cheatsheet-cmd">${escapeHtml(item.cmd)}</span>
          <span class="cheatsheet-desc">&bull; ${escapeHtml(itemDesc)}</span>
        </div>
        <span class="cheatsheet-copy-hint">${"Copy"}</span>
      `;

      btn.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(item.cmd);
          showToast(`Copied: ${item.cmd}`);
        } catch (err) {
          showToast("Clipboard copy failed");
        }
      });

      li.appendChild(btn);
      list.appendChild(li);
    }

    groupEl.appendChild(header);
    groupEl.appendChild(list);
    DOM.cheatsheetGroups.appendChild(groupEl);
  }
}

// ---------------------------------------------------------------------
// Tab Switching
// ---------------------------------------------------------------------
function switchTab(tab) {
  const isAnalyzer = tab === "analyzer";
  DOM.viewAnalyzer.classList.toggle("is-hidden", !isAnalyzer);
  DOM.viewCheatsheet.classList.toggle("is-hidden", isAnalyzer);
  DOM.tabBtnAnalyzer.classList.toggle("is-active", isAnalyzer);
  DOM.tabBtnCheatsheet.classList.toggle("is-active", !isAnalyzer);
  DOM.tabBtnAnalyzer.setAttribute("aria-selected", String(isAnalyzer));
  DOM.tabBtnCheatsheet.setAttribute("aria-selected", String(!isAnalyzer));
}

// =====================================================================
// Event Listeners & Initialization
// =====================================================================
function initEvents() {
  DOM.tabBtnAnalyzer.addEventListener("click", () => switchTab("analyzer"));
  DOM.tabBtnCheatsheet.addEventListener("click", () => switchTab("cheatsheet"));

  // Language Switching Buttons
  if (DOM.langEnBtn) {
    DOM.langEnBtn.addEventListener("click", () => setLanguage("en"));
  }
  if (DOM.langHeBtn) {
    DOM.langHeBtn.addEventListener("click", () => setLanguage("he"));
  }

  // Audit Profile Mode Controls
  

  // Dual Workspace Tab Toggle: HTML Report vs Plain Text
  if (DOM.tabBtnHtml) {
    DOM.tabBtnHtml.addEventListener("click", () => switchWorkspaceView("html"));
  }
  if (DOM.tabBtnPlain) {
    DOM.tabBtnPlain.addEventListener("click", () => switchWorkspaceView("plain"));
  }

  // Browse Link
  if (DOM.browseBtn) {
    DOM.browseBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      DOM.fileInput.click();
    });
  }

  // Copy for ClickUp Button in Plain Text View
  if (DOM.btnCopyClickup) {
    DOM.btnCopyClickup.addEventListener("click", async () => {
      if (!currentFindings.length) {
        showToast("No findings to copy");
        return;
      }
      const { findings, kind, opts } = getExportPayload();
      const plainReport = generateCleanPlainText(findings, kind, opts);
      try {
        await navigator.clipboard.writeText(plainReport);
        showToast("Plain text report for ClickUp copied!");
      } catch (err) {
        showToast("Clipboard copy failed");
      }
    });
  }

  // Audit Profile Dropdown Selector (compatibility fallback)
  

  // Filter: Issues Only Toggle
  if (DOM.filterIssuesOnly) {
    DOM.filterIssuesOnly.addEventListener("change", (e) => {
      issuesOnly = e.target.checked;
      try {
        localStorage.setItem("secops_issues_only", issuesOnly ? "true" : "false");
      } catch (err) {}
      renderFindings(currentFindings);
      updateSummaryCounters(currentFindings);
      if (DOM.plainTextOutput && currentFindings.length > 0) {
        const { findings, kind, opts } = getExportPayload();
        DOM.plainTextOutput.textContent = generateCleanPlainText(findings, kind, opts);
      }
    });
  }

  // Paste Accordion Toggle
  if (DOM.pasteToggleBtn && DOM.pasteBody) {
    DOM.pasteToggleBtn.addEventListener("click", () => {
      const isExpanded = DOM.pasteToggleBtn.getAttribute("aria-expanded") === "true";
      DOM.pasteToggleBtn.setAttribute("aria-expanded", !isExpanded);
      DOM.pasteBody.classList.toggle("is-collapsed", isExpanded);
      if (!isExpanded && DOM.cliInput) {
        DOM.cliInput.focus();
      }
    });
  }

  // Input changes
  if (DOM.cliInput) {
    DOM.cliInput.addEventListener("input", () => {
      updateCharCounter();
      updateDetectBadge(detectInputKind(DOM.cliInput.value || ""));
      updateVerifiedHash(DOM.cliInput.value || "");
    });
  }

  // Action Buttons
  if (DOM.analyzeBtn) {
    DOM.analyzeBtn.addEventListener("click", () => {
      let rawText = DOM.cliInput ? DOM.cliInput.value || "" : "";
      if (!rawText.trim() && loadedFiles.length > 0) {
        rawText = loadedFiles.map((f) => f.content).join("\n\n");
        if (DOM.cliInput) DOM.cliInput.value = rawText;
      }
      if (!rawText.trim() && loadedFiles.length === 0) {
        showToast("No data to analyze");
        if (DOM.pasteToggleBtn && DOM.pasteBody) {
          DOM.pasteToggleBtn.setAttribute("aria-expanded", "true");
          DOM.pasteBody.classList.remove("is-collapsed");
          if (DOM.cliInput) DOM.cliInput.focus();
        }
        return;
      }
      const kind = detectInputKind(rawText);
      updateDetectBadge(kind);
      updateTimestamp();
      currentFindings = runAnalysis(rawText, loadedFiles);
      renderFindings(currentFindings);
      updateSummaryCounters(currentFindings);
      setExportButtonsEnabled(true);
      if (DOM.plainTextOutput) {
        const { findings, opts } = getExportPayload();
        DOM.plainTextOutput.textContent = generateCleanPlainText(findings, kind, opts);
      }
      updateVerifiedHash(rawText);
      const issuesCount = currentFindings.filter((f) => f.status === "FAIL" || f.status === "WARN").length;
      if (issuesCount > 0) {
        showToast(`Analysis complete: ${issuesCount} item(s) require attention`);
      } else {
        showToast("Analysis complete: All checks passing");
      }
    });
  }

  if (DOM.clearBtn) {
    DOM.clearBtn.addEventListener("click", () => {
      clearAllFiles();
      if (DOM.cliInput) DOM.cliInput.value = "";
      updateCharCounter();
      currentFindings = [];
      renderFindings(currentFindings);
      updateSummaryCounters(currentFindings);
      setExportButtonsEnabled(false);
      updateDetectBadge("none");
      updateSummaryIndicator(0, 0);
      updateVerifiedHash("");
      if (DOM.plainTextOutput) {
        DOM.plainTextOutput.textContent = "No analysis executed yet. Run Analyze Security to generate report.";
      }
      const deltaBanner = document.querySelector(".delta-backup-banner");
      if (deltaBanner) deltaBanner.style.display = "none";
      showToast("Cleared");
    });
  }

  // Export Buttons
  if (DOM.copyRichTextBtn) {
    DOM.copyRichTextBtn.addEventListener("click", async () => {
      if (!checkIssuesExportAllowed()) return;
      const { findings, kind, opts } = getExportPayload();
      const htmlReport = generateRichTextHtml(findings, kind, opts);
      try {
        await navigator.clipboard.write([
          new ClipboardItem({
            "text/html": new Blob([htmlReport], { type: "text/html" }),
            "text/plain": new Blob([generateCleanPlainText(findings, kind, opts)], { type: "text/plain" })
          })
        ]);
        showToast(UI_STRINGS[currentLang].toastCopiedRich || "Copied Rich Text!");
      } catch (err) {
        try {
          await navigator.clipboard.writeText(generateCleanPlainText(findings, kind, opts));
          showToast(UI_STRINGS[currentLang].toastCopiedPlain || "Copied Plain Text!");
        } catch (fallbackErr) {
          showToast("Clipboard copy failed");
        }
      }
    });
  }

  if (DOM.copyPlainTextBtn) {
    DOM.copyPlainTextBtn.addEventListener("click", async () => {
      if (!checkIssuesExportAllowed()) return;
      const { findings, kind, opts } = getExportPayload();
      const plainReport = generateCleanPlainText(findings, kind, opts);
      try {
        await navigator.clipboard.writeText(plainReport);
        showToast(UI_STRINGS[currentLang].toastCopiedPlain || "Copied Plain Text!");
      } catch (err) {
        showToast("Clipboard copy failed");
      }
    });
  }

  if (DOM.downloadHtmlBtn) {
    DOM.downloadHtmlBtn.addEventListener("click", () => {
      if (!checkIssuesExportAllowed()) return;
      const { findings, kind, opts } = getExportPayload();
      const docHtml = generateStandaloneHtmlDocument(findings, kind, opts);
      const blob = new Blob([docHtml], { type: "text/html;charset=utf-8" });
      downloadBlob(blob, `SecOps_Audit_Report_${getFormattedTimestampFilename()}.html`);
      showToast(UI_STRINGS[currentLang].toastDownloaded || "HTML Report downloaded");
    });
  }

  if (DOM.downloadTxtBtn) {
    DOM.downloadTxtBtn.addEventListener("click", () => {
      if (!checkIssuesExportAllowed()) return;
      const { findings, kind, opts } = getExportPayload();
      const txtReport = generateCleanPlainText(findings, kind, opts);
      const blob = new Blob([txtReport], { type: "text/plain;charset=utf-8" });
      downloadBlob(blob, `SecOps_Audit_Report_${getFormattedTimestampFilename()}.txt`);
      showToast(UI_STRINGS[currentLang].toastDownloaded || "Text Report downloaded");
    });
  }

  // File Drag & Drop
  if (DOM.dropZone && DOM.fileInput) {
    DOM.dropZone.addEventListener("click", () => {
      DOM.fileInput.click();
    });
    DOM.dropZone.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        DOM.fileInput.click();
      }
    });
    DOM.dropZone.addEventListener("dragover", (e) => {
      e.preventDefault();
      DOM.dropZone.classList.add("is-dragover");
    });
    DOM.dropZone.addEventListener("dragleave", (e) => {
      e.preventDefault();
      DOM.dropZone.classList.remove("is-dragover");
    });
    DOM.dropZone.addEventListener("drop", (e) => {
      e.preventDefault();
      DOM.dropZone.classList.remove("is-dragover");
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        handleFiles(e.dataTransfer.files);
      }
    });
    DOM.fileInput.addEventListener("change", (e) => {
      if (e.target && e.target.files && e.target.files.length > 0) {
        handleFiles(e.target.files);
      }
    });
  }

  if (DOM.clearAllFilesBtn) {
    DOM.clearAllFilesBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      clearAllFiles();
      showToast("All files cleared");
    });
  }
}

// Initialize App
document.addEventListener("DOMContentLoaded", () => {
  if (DOM.filterIssuesOnly) {
    DOM.filterIssuesOnly.checked = issuesOnly;
  }
  setLanguage(currentLang);
  initEvents();
  setInterval(updateTimestamp, 1000);
  updateTimestamp();
});
