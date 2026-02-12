import { NextRequest } from "next/server"
import {
  createInitialState,
  performRecon,
  analyzeVulnerabilities,
  executeExploit,
  attemptPrivilegeEscalation,
  establishPersistence,
  performLateralMovement,
} from "@/lib/redteam/simulation-engine"
import type { AttackState, AttackLogEntry, MitreMapping } from "@/lib/redteam/types"

export async function POST(request: NextRequest) {
  const body = await request.json()
  const { target } = body

  if (!target) {
    return Response.json({ error: "Target IP is required" }, { status: 400 })
  }

  // Validate IP format
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/
  const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/
  if (!ipRegex.test(target) && !cidrRegex.test(target)) {
    return Response.json({ error: "Invalid IP address or CIDR format" }, { status: 400 })
  }

  const state = createInitialState(target)
  state.startTime = new Date().toISOString()
  const allLogs: AttackLogEntry[] = []
  const allMitreMappings: MitreMapping[] = []

  // --- Phase 1: Reconnaissance ---
  state.phase = "recon"
  allLogs.push({
    timestamp: new Date().toISOString(),
    phase: "recon",
    message: "=== PHASE 1: RECONNAISSANCE ===",
    level: "info",
  })

  const reconData = performRecon(state)
  state.reconResult = reconData.reconResult
  allLogs.push(...reconData.logs)
  allMitreMappings.push(reconData.mitreMapping)

  // --- Phase 2: Scanning (included in recon) ---
  state.phase = "scanning"
  allLogs.push({
    timestamp: new Date().toISOString(),
    phase: "scanning",
    message: "=== PHASE 2: SERVICE SCANNING ===",
    level: "info",
  })
  allLogs.push({
    timestamp: new Date().toISOString(),
    phase: "scanning",
    message: `Deep service fingerprinting on ${reconData.reconResult.ports.length} ports...`,
    level: "info",
  })
  allLogs.push({
    timestamp: new Date().toISOString(),
    phase: "scanning",
    message: "Service fingerprinting complete. Proceeding to vulnerability analysis.",
    level: "success",
  })

  // --- Phase 3: Analysis ---
  state.phase = "analysis"
  allLogs.push({
    timestamp: new Date().toISOString(),
    phase: "analysis",
    message: "=== PHASE 3: VULNERABILITY ANALYSIS ===",
    level: "info",
  })

  const analysisData = analyzeVulnerabilities(reconData.reconResult)
  state.vulnerabilities = analysisData.vulnerabilities
  allLogs.push(...analysisData.logs)

  // --- Phase 4: Exploitation ---
  state.phase = "exploitation"
  allLogs.push({
    timestamp: new Date().toISOString(),
    phase: "exploitation",
    message: "=== PHASE 4: EXPLOITATION ===",
    level: "info",
  })

  // Orchestrator: attempt exploits by severity (highest CVSS first)
  for (const vuln of state.vulnerabilities) {
    const exploitData = executeExploit(vuln, state.accessLevel)
    state.exploitResults.push(exploitData.result)
    allLogs.push(...exploitData.logs)
    allMitreMappings.push(exploitData.mitreMapping)

    if (exploitData.result.success) {
      state.accessLevel = exploitData.result.accessGained
      state.compromisedHosts.push(target)

      if (vuln.cvss >= 9.0) {
        state.credentials.push({
          username: "admin",
          hash: "$6$rounds=5000$saltsalt$" + Math.random().toString(36).substring(2, 30),
          source: vuln.exploit,
        })
      }

      break // stop after first successful exploit
    }
  }

  // --- Phase 5: Privilege Escalation ---
  if (state.accessLevel !== "none" && state.accessLevel !== "root") {
    state.phase = "privilege_escalation"
    allLogs.push({
      timestamp: new Date().toISOString(),
      phase: "privilege_escalation",
      message: "=== PHASE 5: PRIVILEGE ESCALATION ===",
      level: "info",
    })

    const privescData = attemptPrivilegeEscalation(
      state.accessLevel,
      reconData.reconResult.os.family
    )
    state.privescResult = privescData.result
    allLogs.push(...privescData.logs)
    allMitreMappings.push(privescData.mitreMapping)

    if (privescData.result.success) {
      state.accessLevel = privescData.result.newLevel
    }
  }

  // --- Phase 6: Persistence ---
  if (state.accessLevel === "admin" || state.accessLevel === "root") {
    state.phase = "persistence"
    allLogs.push({
      timestamp: new Date().toISOString(),
      phase: "persistence",
      message: "=== PHASE 6: PERSISTENCE ===",
      level: "info",
    })

    const persistData = establishPersistence(
      reconData.reconResult.os.family,
      state.accessLevel
    )
    state.persistenceResult = persistData.result
    allLogs.push(...persistData.logs)
    allMitreMappings.push(persistData.mitreMapping)
  }

  // --- Phase 7: Lateral Movement ---
  if (state.accessLevel === "admin" || state.accessLevel === "root") {
    state.phase = "lateral_movement"
    allLogs.push({
      timestamp: new Date().toISOString(),
      phase: "lateral_movement",
      message: "=== PHASE 7: LATERAL MOVEMENT ===",
      level: "info",
    })

    const lateralData = performLateralMovement(target, state.credentials)
    state.lateralMovementResults = lateralData.results
    allLogs.push(...lateralData.logs)
    allMitreMappings.push(...lateralData.mitreMappings)

    const successfulMoves = lateralData.results.filter((r) => r.success)
    successfulMoves.forEach((move) => {
      state.compromisedHosts.push(move.targetHost)
    })
  }

  // --- Phase 8: Reporting ---
  state.phase = "complete"
  state.endTime = new Date().toISOString()
  state.attackHistory = allLogs
  state.mitreMapping = allMitreMappings

  allLogs.push({
    timestamp: new Date().toISOString(),
    phase: "reporting",
    message: "=== PHASE 8: GENERATING REPORT ===",
    level: "info",
  })
  allLogs.push({
    timestamp: new Date().toISOString(),
    phase: "reporting",
    message: `Attack simulation complete. Final access level: ${state.accessLevel}. Compromised hosts: ${state.compromisedHosts.length}.`,
    level: "success",
  })

  return Response.json({
    state,
    logs: allLogs,
    mitreMapping: allMitreMappings,
    summary: {
      target,
      startTime: state.startTime,
      endTime: state.endTime,
      finalAccessLevel: state.accessLevel,
      compromisedHosts: state.compromisedHosts,
      credentialsObtained: state.credentials.length,
      vulnerabilitiesFound: state.vulnerabilities.length,
      exploitsAttempted: state.exploitResults.length,
      successfulExploits: state.exploitResults.filter((r) => r.success).length,
      persistenceEstablished: state.persistenceResult?.success ?? false,
      lateralMovementSuccesses: state.lateralMovementResults.filter((r) => r.success).length,
      mitreTechniquesUsed: [...new Set(allMitreMappings.map((m) => m.technique.id))],
    },
  })
}
