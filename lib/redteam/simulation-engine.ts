import type {
  AttackState,
  AttackLogEntry,
  AttackPhase,
  ReconResult,
  Vulnerability,
  ExploitResult,
  PrivEscResult,
  PersistenceResult,
  LateralMovementResult,
  MitreMapping,
  AccessLevel,
} from "./types"
import {
  MITRE_TECHNIQUES,
  generateScanResults,
  generateOSDetection,
  matchVulnerabilities,
} from "./knowledge-base"

function timestamp(): string {
  return new Date().toISOString()
}

export function createInitialState(target: string): AttackState {
  return {
    phase: "idle",
    target,
    accessLevel: "none",
    compromisedHosts: [],
    credentials: [],
    attackHistory: [],
    reconResult: null,
    vulnerabilities: [],
    exploitResults: [],
    privescResult: null,
    persistenceResult: null,
    lateralMovementResults: [],
    mitreMapping: [],
    startTime: null,
    endTime: null,
  }
}

// --- RECON MODULE (fully dynamic per IP) ---
export function performRecon(state: AttackState): {
  reconResult: ReconResult
  logs: AttackLogEntry[]
  mitreMapping: MitreMapping
} {
  const logs: AttackLogEntry[] = [
    {
      timestamp: timestamp(),
      phase: "recon",
      message: `Initiating nmap service scan on target ${state.target}`,
      level: "info",
      mitreTechnique: MITRE_TECHNIQUES.T1595,
    },
    {
      timestamp: timestamp(),
      phase: "recon",
      message: `Running: nmap -sV -sC -O -Pn -T4 ${state.target}`,
      level: "info",
    },
  ]

  // Dynamic port/service discovery based on target IP
  const scanResults = generateScanResults(state.target)
  const osDetection = generateOSDetection(state.target)

  // Subdomain enumeration
  const subdomainPrefixes = [
    "mail", "vpn", "dev", "staging", "api", "admin", "portal",
    "db", "ftp", "git", "ci", "jenkins", "grafana", "monitor",
    "wiki", "jira", "confluence", "sso", "auth", "cdn",
  ]
  const discoveredSubdomains = subdomainPrefixes
    .filter(() => Math.random() < 0.35)
    .map((prefix) => {
      const alive = Math.random() < 0.65
      return {
        subdomain: `${prefix}.${state.target}`,
        ip: `${state.target.split(".").slice(0, 3).join(".")}.${Math.floor(Math.random() * 254) + 1}`,
        status: alive ? ("alive" as const) : ("dead" as const),
      }
    })

  const aliveCount = discoveredSubdomains.filter((s) => s.status === "alive").length

  logs.push({
    timestamp: timestamp(),
    phase: "recon",
    message: `Subdomain enumeration: discovered ${discoveredSubdomains.length} subdomains (${aliveCount} alive)`,
    level: "success",
  })

  discoveredSubdomains
    .filter((s) => s.status === "alive")
    .forEach((s) => {
      logs.push({
        timestamp: timestamp(),
        phase: "recon",
        message: `  [ALIVE] ${s.subdomain} -> ${s.ip}`,
        level: "info",
      })
    })

  const reconResult: ReconResult = {
    target: state.target,
    timestamp: timestamp(),
    ports: scanResults,
    os: osDetection,
    subdomains: discoveredSubdomains,
    mitreTechnique: MITRE_TECHNIQUES.T1595,
  }

  scanResults.forEach((port) => {
    logs.push({
      timestamp: timestamp(),
      phase: "recon",
      message: `Discovered ${port.state} port ${port.port}/${port.protocol} - ${port.service} ${port.version}`,
      level: port.state === "open" ? "success" : "info",
    })
  })

  logs.push({
    timestamp: timestamp(),
    phase: "recon",
    message: `OS Detection: ${osDetection.name} [${osDetection.family}] (${osDetection.accuracy}% confidence)`,
    level: "info",
  })

  logs.push({
    timestamp: timestamp(),
    phase: "recon",
    message: `Reconnaissance complete. ${scanResults.filter((p) => p.state === "open").length} open ports, ${scanResults.filter((p) => p.state === "filtered").length} filtered.`,
    level: "success",
    mitreTechnique: MITRE_TECHNIQUES.T1595,
  })

  const mitreMapping: MitreMapping = {
    technique: MITRE_TECHNIQUES.T1595,
    phase: "recon",
    result: "success",
    timestamp: timestamp(),
  }

  return { reconResult, logs, mitreMapping }
}

// --- ANALYZER MODULE (dynamic vulnerability matching) ---
export function analyzeVulnerabilities(
  reconResult: ReconResult
): {
  vulnerabilities: Vulnerability[]
  logs: AttackLogEntry[]
} {
  const logs: AttackLogEntry[] = [
    {
      timestamp: timestamp(),
      phase: "analysis",
      message: `Analyzing ${reconResult.ports.filter((p) => p.state === "open").length} open services against vulnerability knowledge base (${reconResult.os.name})...`,
      level: "info",
    },
  ]

  // Dynamically match vulnerabilities to discovered services
  const matchedEntries = matchVulnerabilities(reconResult.ports)

  const vulnerabilities: Vulnerability[] = matchedEntries.map((entry, idx) => {
    const technique = MITRE_TECHNIQUES[entry.technique]
    const port = parseInt(entry.key.split("_")[0])
    const portInfo = reconResult.ports.find((p) => p.port === port)

    return {
      id: `CVE-${2015 + Math.floor(Math.random() * 10)}-${String(Math.floor(Math.random() * 90000) + 10000)}`,
      name: entry.exploit.replace(/_/g, " ").toUpperCase(),
      severity: entry.severity,
      port,
      service: portInfo ? `${portInfo.service} ${portInfo.version}` : entry.key.split("_")[1],
      exploit: entry.exploit,
      mitreTechnique: technique,
      cvss: entry.cvss,
      description: entry.description,
    }
  })

  // Sort by CVSS descending
  vulnerabilities.sort((a, b) => b.cvss - a.cvss)

  vulnerabilities.forEach((v) => {
    logs.push({
      timestamp: timestamp(),
      phase: "analysis",
      message: `[${v.severity.toUpperCase()}] ${v.id} - ${v.exploit} on port ${v.port} (CVSS: ${v.cvss})`,
      level:
        v.severity === "critical" || v.severity === "high"
          ? "warning"
          : "info",
      mitreTechnique: v.mitreTechnique,
    })
  })

  if (vulnerabilities.length === 0) {
    logs.push({
      timestamp: timestamp(),
      phase: "analysis",
      message: "No matching vulnerabilities found for discovered services. Target may be hardened.",
      level: "warning",
    })
  } else {
    logs.push({
      timestamp: timestamp(),
      phase: "analysis",
      message: `Analysis complete. ${vulnerabilities.length} candidate exploits identified (${vulnerabilities.filter((v) => v.severity === "critical").length} critical, ${vulnerabilities.filter((v) => v.severity === "high").length} high).`,
      level: "success",
    })
  }

  return { vulnerabilities, logs }
}

// --- EXPLOIT ENGINE ---
export function executeExploit(
  vulnerability: Vulnerability,
  currentAccess: AccessLevel
): {
  result: ExploitResult
  logs: AttackLogEntry[]
  mitreMapping: MitreMapping
} {
  const logs: AttackLogEntry[] = []

  const successChance =
    vulnerability.severity === "critical"
      ? 0.92
      : vulnerability.severity === "high"
        ? 0.75
        : vulnerability.severity === "medium"
          ? 0.55
          : 0.25

  const success = Math.random() < successChance
  const accessGained: AccessLevel = success
    ? vulnerability.cvss >= 9.0
      ? "admin"
      : vulnerability.cvss >= 7.0
        ? "user"
        : currentAccess
    : currentAccess

  // AI Decision Reasoning
  logs.push({
    timestamp: timestamp(),
    phase: "exploitation",
    message: `[AI-DECISION] Evaluating ${vulnerability.exploit} (${vulnerability.id}, CVSS: ${vulnerability.cvss}). Service: ${vulnerability.service} on port ${vulnerability.port}. Estimated success probability: ${(successChance * 100).toFixed(0)}%. Risk assessment: ${vulnerability.severity}. Current access: ${currentAccess}. Proceeding with exploitation.`,
    level: "info",
  })

  logs.push({
    timestamp: timestamp(),
    phase: "exploitation",
    message: `[EXPLOIT] Launching ${vulnerability.exploit} against ${vulnerability.service} on port ${vulnerability.port}...`,
    level: "info",
    mitreTechnique: vulnerability.mitreTechnique,
  })

  if (success) {
    logs.push({
      timestamp: timestamp(),
      phase: "exploitation",
      message: `[SUCCESS] ${vulnerability.exploit} -> gained ${accessGained}-level shell on target`,
      level: "success",
      mitreTechnique: vulnerability.mitreTechnique,
    })

    if (vulnerability.cvss >= 9.0) {
      const users = ["admin", "root", "svc_account", "dbadmin", "www-data"]
      const user = users[Math.floor(Math.random() * users.length)]
      logs.push({
        timestamp: timestamp(),
        phase: "exploitation",
        message: `  Credentials harvested: ${user}:$6$rounds=5000$${Math.random().toString(36).substring(2, 10)}$...`,
        level: "success",
      })
    }
  } else {
    const reasons = [
      "Target appears patched against this vulnerability.",
      "WAF/IDS blocked payload delivery.",
      "Exploit payload did not trigger - service may be custom build.",
      "Connection reset by peer - firewall rule detected.",
      "Exploit timed out - service may have crash protection.",
    ]
    logs.push({
      timestamp: timestamp(),
      phase: "exploitation",
      message: `[FAILED] ${vulnerability.exploit} - ${reasons[Math.floor(Math.random() * reasons.length)]}`,
      level: "error",
      mitreTechnique: vulnerability.mitreTechnique,
    })
  }

  const result: ExploitResult = {
    vulnerability,
    success,
    accessGained,
    output: success
      ? `Exploit ${vulnerability.exploit} succeeded. Gained ${accessGained} shell.`
      : `Exploit ${vulnerability.exploit} failed.`,
    timestamp: timestamp(),
  }

  const mitreMapping: MitreMapping = {
    technique: vulnerability.mitreTechnique,
    phase: "exploitation",
    result: success ? "success" : "failure",
    timestamp: timestamp(),
  }

  return { result, logs, mitreMapping }
}

// --- PRIVILEGE ESCALATION ENGINE (OS-aware) ---
export function attemptPrivilegeEscalation(
  currentAccess: AccessLevel,
  osFamily: string
): {
  result: PrivEscResult
  logs: AttackLogEntry[]
  mitreMapping: MitreMapping
} {
  const logs: AttackLogEntry[] = []
  const isLinux = osFamily.toLowerCase().includes("linux") || osFamily.toLowerCase().includes("bsd")

  const techniques = isLinux
    ? [
        "SUID binary exploitation (/usr/bin/find -exec)",
        "sudo misconfiguration (NOPASSWD entry for /usr/bin/vim)",
        "Kernel exploit (DirtyCOW CVE-2016-5195)",
        "Writable /etc/passwd (add root-equivalent user)",
        "Cron job wildcard injection (/opt/scripts/backup.sh)",
        "Docker group membership -> container escape",
        "LD_PRELOAD hijack in SUID binary",
        "Polkit CVE-2021-4034 (PwnKit)",
      ]
    : [
        "Unquoted service path exploitation",
        "AlwaysInstallElevated registry abuse",
        "Token impersonation (SeImpersonatePrivilege -> JuicyPotato)",
        "DLL hijacking in writable PATH directory",
        "Scheduled task writable binary replacement",
        "PrintNightmare CVE-2021-34527",
        "HiveNightmare CVE-2021-36934 (SAM dump)",
        "UAC bypass via fodhelper.exe",
      ]

  const chosenTechnique = techniques[Math.floor(Math.random() * techniques.length)]
  const success = Math.random() < 0.82

  logs.push({
    timestamp: timestamp(),
    phase: "privilege_escalation",
    message: `Current access level: ${currentAccess}. Enumerating escalation vectors on ${osFamily}...`,
    level: "info",
  })

  logs.push({
    timestamp: timestamp(),
    phase: "privilege_escalation",
    message: `[AI-DECISION] Detected ${osFamily} environment. Evaluated ${techniques.length} escalation paths: ${techniques.slice(0, 3).join(", ")}... Selected: "${chosenTechnique}" based on OS fingerprint, kernel version, and current ${currentAccess}-level access.`,
    level: "info",
  })

  logs.push({
    timestamp: timestamp(),
    phase: "privilege_escalation",
    message: `Executing: ${chosenTechnique}`,
    level: "info",
    mitreTechnique: MITRE_TECHNIQUES.T1068,
  })

  const newLevel: AccessLevel = success ? "root" : currentAccess

  if (success) {
    logs.push({
      timestamp: timestamp(),
      phase: "privilege_escalation",
      message: `[ESCALATED] ${currentAccess} -> ${newLevel} via ${chosenTechnique}`,
      level: "success",
      mitreTechnique: MITRE_TECHNIQUES.T1068,
    })
    logs.push({
      timestamp: timestamp(),
      phase: "privilege_escalation",
      message: `  uid=0(root) gid=0(root) groups=0(root)`,
      level: "success",
    })
  } else {
    logs.push({
      timestamp: timestamp(),
      phase: "privilege_escalation",
      message: `[FAILED] Privilege escalation via ${chosenTechnique} unsuccessful. Kernel may be patched.`,
      level: "error",
    })
  }

  const result: PrivEscResult = {
    technique: chosenTechnique,
    success,
    previousLevel: currentAccess,
    newLevel,
    output: success
      ? `Privilege escalation succeeded via ${chosenTechnique}. Now running as ${newLevel}.`
      : `Privilege escalation failed. Remaining at ${currentAccess} level.`,
    mitreTechnique: MITRE_TECHNIQUES.T1068,
    timestamp: timestamp(),
  }

  const mitreMapping: MitreMapping = {
    technique: MITRE_TECHNIQUES.T1068,
    phase: "privilege_escalation",
    result: success ? "success" : "failure",
    timestamp: timestamp(),
  }

  return { result, logs, mitreMapping }
}

// --- PERSISTENCE ENGINE ---
export function establishPersistence(
  osFamily: string,
  accessLevel: AccessLevel
): {
  result: PersistenceResult
  logs: AttackLogEntry[]
  mitreMapping: MitreMapping
} {
  const logs: AttackLogEntry[] = []
  const isLinux = osFamily.toLowerCase().includes("linux") || osFamily.toLowerCase().includes("bsd")

  const methods = isLinux
    ? [
        "Cron job persistence (/etc/cron.d/system-update)",
        "SSH authorized_keys backdoor (~/.ssh/authorized_keys)",
        "Systemd service backdoor (/etc/systemd/system/svc-helper.service)",
        "Bash profile hook (~/.bashrc reverse shell)",
        "PAM backdoor module (/lib/security/pam_backdoor.so)",
      ]
    : [
        "Registry Run Key (HKLM\\...\\CurrentVersion\\Run)",
        "Scheduled Task (schtasks /create /tn UpdateCheck)",
        "WMI Event Subscription persistence",
        "DLL side-loading in System32",
        "Service binary replacement (svc_helper.exe)",
      ]

  const method = methods[Math.floor(Math.random() * methods.length)]
  const technique = isLinux ? MITRE_TECHNIQUES.T1053 : MITRE_TECHNIQUES.T1547
  const success = accessLevel === "root" || accessLevel === "admin" ? true : Math.random() < 0.5

  logs.push({
    timestamp: timestamp(),
    phase: "persistence",
    message: `[AI-DECISION] Selecting persistence mechanism for ${osFamily} with ${accessLevel}-level access. Chosen: ${method}`,
    level: "info",
  })

  logs.push({
    timestamp: timestamp(),
    phase: "persistence",
    message: `Installing: ${method}`,
    level: "info",
    mitreTechnique: technique,
  })

  if (success) {
    logs.push({
      timestamp: timestamp(),
      phase: "persistence",
      message: `[PERSISTED] Backdoor installed via ${method}. Will survive reboot.`,
      level: "success",
      mitreTechnique: technique,
    })
  } else {
    logs.push({
      timestamp: timestamp(),
      phase: "persistence",
      message: `[FAILED] Insufficient privileges (${accessLevel}) for ${method}`,
      level: "error",
    })
  }

  const result: PersistenceResult = {
    method,
    success,
    output: success
      ? `Persistence established via ${method}.`
      : `Persistence failed. Insufficient access (${accessLevel}).`,
    mitreTechnique: technique,
    timestamp: timestamp(),
  }

  const mitreMapping: MitreMapping = {
    technique,
    phase: "persistence",
    result: success ? "success" : "failure",
    timestamp: timestamp(),
  }

  return { result, logs, mitreMapping }
}

// --- LATERAL MOVEMENT ---
export function performLateralMovement(
  target: string,
  credentials: { username: string; hash: string; source: string }[]
): {
  results: LateralMovementResult[]
  logs: AttackLogEntry[]
  mitreMappings: MitreMapping[]
} {
  const logs: AttackLogEntry[] = []
  const results: LateralMovementResult[] = []
  const mitreMappings: MitreMapping[] = []

  const baseIP = target.split(".").slice(0, 3).join(".")
  const lastOctet = parseInt(target.split(".")[3]) || 1
  const targetCount = 2 + Math.floor(Math.random() * 4) // 2-5 lateral targets
  const lateralTargets: string[] = []

  for (let i = 0; i < targetCount; i++) {
    let octet = lastOctet + Math.floor(Math.random() * 50) + 1
    if (octet > 254) octet = Math.floor(Math.random() * 254) + 1
    lateralTargets.push(`${baseIP}.${octet}`)
  }

  const methods = credentials.length > 0
    ? ["Pass-the-Hash (PtH)", "Credential reuse via SSH", "WMI remote execution", "PsExec with harvested creds"]
    : ["SMB relay attack", "LLMNR/NBT-NS poisoning", "ARP spoofing + credential capture", "Kerberoasting"]

  logs.push({
    timestamp: timestamp(),
    phase: "lateral_movement",
    message: `Scanning internal subnet ${baseIP}.0/24 for ${lateralTargets.length} lateral movement targets...`,
    level: "info",
    mitreTechnique: MITRE_TECHNIQUES.T1021,
  })

  lateralTargets.forEach((lateralTarget) => {
    const success = Math.random() < 0.55
    const method = methods[Math.floor(Math.random() * methods.length)]

    logs.push({
      timestamp: timestamp(),
      phase: "lateral_movement",
      message: `[AI-DECISION] Targeting ${lateralTarget}. Method: ${method}. ${credentials.length > 0 ? `Using ${credentials.length} harvested credential(s).` : "No credentials available, attempting relay/poisoning."}`,
      level: "info",
    })

    logs.push({
      timestamp: timestamp(),
      phase: "lateral_movement",
      message: `Attempting ${method} on ${lateralTarget}...`,
      level: "info",
    })

    if (success) {
      logs.push({
        timestamp: timestamp(),
        phase: "lateral_movement",
        message: `[PIVOTED] Successfully moved to ${lateralTarget} via ${method}`,
        level: "success",
        mitreTechnique: MITRE_TECHNIQUES.T1021,
      })
    } else {
      const failReasons = [
        "Host unreachable - may be firewalled",
        "Credentials invalid on this host",
        "Service not running on target",
        "EDR blocked lateral movement attempt",
      ]
      logs.push({
        timestamp: timestamp(),
        phase: "lateral_movement",
        message: `[BLOCKED] ${lateralTarget} - ${failReasons[Math.floor(Math.random() * failReasons.length)]}`,
        level: "error",
      })
    }

    results.push({
      targetHost: lateralTarget,
      method,
      success,
      output: success
        ? `Lateral movement to ${lateralTarget} succeeded via ${method}.`
        : `Lateral movement to ${lateralTarget} failed.`,
      mitreTechnique: MITRE_TECHNIQUES.T1021,
      timestamp: timestamp(),
    })

    mitreMappings.push({
      technique: MITRE_TECHNIQUES.T1021,
      phase: "lateral_movement",
      result: success ? "success" : "failure",
      timestamp: timestamp(),
    })
  })

  return { results, logs, mitreMappings }
}

// --- ORCHESTRATOR (Decision Engine) ---
export function getNextPhase(state: AttackState): AttackPhase {
  if (state.phase === "idle") return "recon"
  if (state.phase === "recon") return "scanning"
  if (state.phase === "scanning") return "analysis"

  if (state.accessLevel === "none") {
    if (state.vulnerabilities.length > 0 && state.exploitResults.length === 0) {
      return "exploitation"
    }
    if (state.exploitResults.length > 0 && state.exploitResults.every((r) => !r.success)) {
      const exploitedVulns = new Set(state.exploitResults.map((r) => r.vulnerability.id))
      const unexploited = state.vulnerabilities.filter((v) => !exploitedVulns.has(v.id))
      if (unexploited.length > 0) return "exploitation"
    }
    return "analysis"
  }

  if (state.accessLevel === "user") {
    if (!state.privescResult) return "privilege_escalation"
    if (state.privescResult && !state.privescResult.success) return "privilege_escalation"
  }

  if (state.accessLevel === "admin" || state.accessLevel === "root") {
    if (!state.persistenceResult) return "persistence"
    if (state.lateralMovementResults.length === 0) return "lateral_movement"
  }

  return "reporting"
}
