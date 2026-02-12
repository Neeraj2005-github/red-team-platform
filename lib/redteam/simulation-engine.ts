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
  KNOWLEDGE_BASE,
  SERVICE_SCAN_RESULTS,
  OS_DETECTION,
} from "./knowledge-base"

function timestamp(): string {
  return new Date().toISOString()
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
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

// --- RECON MODULE ---
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
      message: `Running: nmap -sV -O -Pn ${state.target}`,
      level: "info",
    },
  ]

  // Subdomain enumeration
  const baseDomain = state.target
  const subdomainPrefixes = ["mail", "vpn", "dev", "staging", "api", "admin", "portal", "db", "ftp", "git"]
  const discoveredSubdomains = subdomainPrefixes
    .filter(() => Math.random() < 0.5)
    .map((prefix) => {
      const alive = Math.random() < 0.7
      return {
        subdomain: `${prefix}.${baseDomain}`,
        ip: `${state.target.split(".").slice(0, 3).join(".")}.${Math.floor(Math.random() * 254) + 1}`,
        status: alive ? ("alive" as const) : ("dead" as const),
      }
    })

  logs.push({
    timestamp: timestamp(),
    phase: "recon" as const,
    message: `Subdomain enumeration: discovered ${discoveredSubdomains.length} subdomains (${discoveredSubdomains.filter((s) => s.status === "alive").length} alive)`,
    level: "success",
  })

  discoveredSubdomains
    .filter((s) => s.status === "alive")
    .forEach((s) => {
      logs.push({
        timestamp: timestamp(),
        phase: "recon" as const,
        message: `  [ALIVE] ${s.subdomain} -> ${s.ip}`,
        level: "info",
      })
    })

  const reconResult: ReconResult = {
    target: state.target,
    timestamp: timestamp(),
    ports: SERVICE_SCAN_RESULTS,
    os: OS_DETECTION,
    subdomains: discoveredSubdomains,
    mitreTechnique: MITRE_TECHNIQUES.T1595,
  }

  SERVICE_SCAN_RESULTS.forEach((port) => {
    logs.push({
      timestamp: timestamp(),
      phase: "recon",
      message: `Discovered ${port.state} port ${port.port}/${port.protocol} - ${port.service} ${port.version}`,
      level: "success",
    })
  })

  logs.push({
    timestamp: timestamp(),
    phase: "recon",
    message: `OS Detection: ${OS_DETECTION.name} (${OS_DETECTION.accuracy}% confidence)`,
    level: "info",
  })

  logs.push({
    timestamp: timestamp(),
    phase: "recon",
    message: `Reconnaissance complete. ${SERVICE_SCAN_RESULTS.length} open ports discovered.`,
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

// --- ANALYZER MODULE ---
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
      message: "Analyzing discovered services against knowledge base...",
      level: "info",
    },
  ]

  const vulnerabilities: Vulnerability[] = []

  reconResult.ports.forEach((port) => {
    const serviceKey = `${port.port}_${port.service.split("-")[0]}`
    const matchingEntries = KNOWLEDGE_BASE.filter((entry) => {
      const entryPort = parseInt(entry.key.split("_")[0])
      return entryPort === port.port
    })

    matchingEntries.forEach((entry) => {
      const technique = MITRE_TECHNIQUES[entry.technique]
      const vuln: Vulnerability = {
        id: `VULN-${vulnerabilities.length + 1}`,
        name: entry.exploit.replace(/_/g, " ").toUpperCase(),
        severity: entry.severity,
        port: port.port,
        service: `${port.service} ${port.version}`,
        exploit: entry.exploit,
        mitreTechnique: technique,
        cvss: entry.cvss,
        description: entry.description,
      }
      vulnerabilities.push(vuln)

      logs.push({
        timestamp: timestamp(),
        phase: "analysis",
        message: `[${entry.severity.toUpperCase()}] ${entry.exploit} matched on port ${port.port} (CVSS: ${entry.cvss})`,
        level:
          entry.severity === "critical" || entry.severity === "high"
            ? "warning"
            : "info",
        mitreTechnique: technique,
      })
    })
  })

  // Sort by CVSS score descending
  vulnerabilities.sort((a, b) => b.cvss - a.cvss)

  logs.push({
    timestamp: timestamp(),
    phase: "analysis",
    message: `Analysis complete. ${vulnerabilities.length} candidate exploits identified.`,
    level: "success",
  })

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

  // Decision engine: choose best exploit
  const successChance =
    vulnerability.severity === "critical"
      ? 0.95
      : vulnerability.severity === "high"
        ? 0.8
        : vulnerability.severity === "medium"
          ? 0.6
          : 0.3

  const success = Math.random() < successChance
  const accessGained: AccessLevel = success
    ? vulnerability.cvss >= 9.0
      ? "admin"
      : "user"
    : currentAccess

  // AI Decision Reasoning
  logs.push({
    timestamp: timestamp(),
    phase: "exploitation",
    message: `[AI-DECISION] Selected ${vulnerability.exploit} (CVSS: ${vulnerability.cvss}) over ${vulnerability.severity === "critical" ? "lower-severity alternatives" : "other candidates"}. Rationale: port ${vulnerability.port}/${vulnerability.service} matches knowledge base signature with ${(successChance * 100).toFixed(0)}% estimated success rate. Current access: ${currentAccess}.`,
    level: "info",
  })

  logs.push({
    timestamp: timestamp(),
    phase: "exploitation",
    message: `[EXPLOIT] Attempting ${vulnerability.exploit} on port ${vulnerability.port}...`,
    level: "info",
    mitreTechnique: vulnerability.mitreTechnique,
  })

  if (success) {
    logs.push({
      timestamp: timestamp(),
      phase: "exploitation",
      message: `[SUCCESS] ${vulnerability.exploit} - ${accessGained} access gained!`,
      level: "success",
      mitreTechnique: vulnerability.mitreTechnique,
    })

    if (vulnerability.cvss >= 9.0) {
      logs.push({
        timestamp: timestamp(),
        phase: "exploitation",
        message: `Credentials harvested: admin:$6$rounds=5000$salt$hash...`,
        level: "success",
      })
    }
  } else {
    logs.push({
      timestamp: timestamp(),
      phase: "exploitation",
      message: `[FAILED] ${vulnerability.exploit} - Exploit did not succeed. Target may be patched.`,
      level: "error",
      mitreTechnique: vulnerability.mitreTechnique,
    })
  }

  const result: ExploitResult = {
    vulnerability,
    success,
    accessGained,
    output: success
      ? `Exploit ${vulnerability.exploit} succeeded. Gained ${accessGained} shell on ${vulnerability.port}/${vulnerability.service}.`
      : `Exploit ${vulnerability.exploit} failed. Service may be patched or firewall rules blocked payload delivery.`,
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

// --- PRIVILEGE ESCALATION ENGINE ---
export function attemptPrivilegeEscalation(
  currentAccess: AccessLevel,
  osFamily: string
): {
  result: PrivEscResult
  logs: AttackLogEntry[]
  mitreMapping: MitreMapping
} {
  const logs: AttackLogEntry[] = []
  const isLinux = osFamily.toLowerCase().includes("linux")

  const techniques = isLinux
    ? [
        "SUID binary exploitation (/usr/bin/find)",
        "sudo misconfiguration (NOPASSWD)",
        "Kernel exploit (DirtyCOW CVE-2016-5195)",
      ]
    : [
        "Unquoted service path exploitation",
        "AlwaysInstallElevated registry abuse",
        "Token impersonation (SeImpersonatePrivilege)",
      ]

  const chosenTechnique = techniques[Math.floor(Math.random() * techniques.length)]
  const success = Math.random() < 0.85

  logs.push({
    timestamp: timestamp(),
    phase: "privilege_escalation",
    message: `Current access level: ${currentAccess}. Attempting privilege escalation...`,
    level: "info",
  })

  logs.push({
    timestamp: timestamp(),
    phase: "privilege_escalation",
    message: `[AI-DECISION] Detected ${isLinux ? "Linux" : "Windows"} environment. Evaluated ${techniques.length} escalation paths. Selected: "${chosenTechnique}" based on OS fingerprint and current ${currentAccess}-level access.`,
    level: "info",
  })

  logs.push({
    timestamp: timestamp(),
    phase: "privilege_escalation",
    message: `Technique selected: ${chosenTechnique}`,
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
  } else {
    logs.push({
      timestamp: timestamp(),
      phase: "privilege_escalation",
      message: `[FAILED] Privilege escalation unsuccessful. Trying fallback...`,
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
  const isLinux = osFamily.toLowerCase().includes("linux")

  const method = isLinux
    ? "Cron job persistence (/etc/cron.d/update-check)"
    : "Registry Run Key (HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)"

  const technique = isLinux ? MITRE_TECHNIQUES.T1053 : MITRE_TECHNIQUES.T1547
  const success = accessLevel === "root" || accessLevel === "admin" ? true : Math.random() < 0.6

  logs.push({
    timestamp: timestamp(),
    phase: "persistence",
    message: `Establishing persistence mechanism: ${method}`,
    level: "info",
    mitreTechnique: technique,
  })

  if (success) {
    logs.push({
      timestamp: timestamp(),
      phase: "persistence",
      message: `[PERSISTED] Backdoor installed via ${isLinux ? "cron job" : "registry key"}`,
      level: "success",
      mitreTechnique: technique,
    })
  } else {
    logs.push({
      timestamp: timestamp(),
      phase: "persistence",
      message: `[FAILED] Insufficient privileges for persistence mechanism`,
      level: "error",
    })
  }

  const result: PersistenceResult = {
    method,
    success,
    output: success
      ? `Persistence established via ${method}. Backdoor will survive reboot.`
      : `Persistence failed. Insufficient access level (${accessLevel}) for ${method}.`,
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

  // Generate subnet targets
  const baseIP = target.split(".").slice(0, 3).join(".")
  const lastOctet = parseInt(target.split(".")[3])
  const lateralTargets = [
    `${baseIP}.${lastOctet + 1}`,
    `${baseIP}.${lastOctet + 2}`,
    `${baseIP}.${lastOctet + 5}`,
  ]

  logs.push({
    timestamp: timestamp(),
    phase: "lateral_movement",
    message: `Scanning internal subnet ${baseIP}.0/24 for lateral movement targets...`,
    level: "info",
    mitreTechnique: MITRE_TECHNIQUES.T1021,
  })

  lateralTargets.forEach((lateralTarget, index) => {
    const success = Math.random() < 0.6
    const method =
      credentials.length > 0
        ? "Credential reuse (pass-the-hash)"
        : "SMB relay attack"

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
        message: `[MOVED] Successfully pivoted to ${lateralTarget} via ${method}`,
        level: "success",
        mitreTechnique: MITRE_TECHNIQUES.T1021,
      })
    } else {
      logs.push({
        timestamp: timestamp(),
        phase: "lateral_movement",
        message: `[BLOCKED] Failed to move to ${lateralTarget} - host unreachable or credentials invalid`,
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

  // Rule-based decision scoring
  if (state.accessLevel === "none") {
    if (state.vulnerabilities.length > 0 && state.exploitResults.length === 0) {
      return "exploitation"
    }
    if (state.exploitResults.length > 0 && state.exploitResults.every((r) => !r.success)) {
      // Try more exploits if we have more vulnerabilities
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
