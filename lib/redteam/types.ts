export type AttackPhase =
  | "idle"
  | "recon"
  | "scanning"
  | "analysis"
  | "exploitation"
  | "privilege_escalation"
  | "persistence"
  | "lateral_movement"
  | "reporting"
  | "complete"

export type AccessLevel = "none" | "user" | "admin" | "root"

export type Severity = "critical" | "high" | "medium" | "low" | "info"

export interface MitreTechnique {
  id: string
  name: string
  tactic: string
  description: string
}

export interface ScanResult {
  port: number
  service: string
  version: string
  state: "open" | "closed" | "filtered"
  protocol: string
}

export interface OSDetection {
  name: string
  family: string
  accuracy: number
}

export interface SubdomainResult {
  subdomain: string
  ip: string
  status: "alive" | "dead"
}

export interface ReconResult {
  target: string
  timestamp: string
  ports: ScanResult[]
  os: OSDetection
  subdomains: SubdomainResult[]
  mitreTechnique: MitreTechnique
}

export interface Vulnerability {
  id: string
  name: string
  severity: Severity
  port: number
  service: string
  exploit: string
  mitreTechnique: MitreTechnique
  cvss: number
  description: string
}

export interface ExploitResult {
  vulnerability: Vulnerability
  success: boolean
  accessGained: AccessLevel
  output: string
  timestamp: string
}

export interface PrivEscResult {
  technique: string
  success: boolean
  previousLevel: AccessLevel
  newLevel: AccessLevel
  output: string
  mitreTechnique: MitreTechnique
  timestamp: string
}

export interface PersistenceResult {
  method: string
  success: boolean
  output: string
  mitreTechnique: MitreTechnique
  timestamp: string
}

export interface LateralMovementResult {
  targetHost: string
  method: string
  success: boolean
  output: string
  mitreTechnique: MitreTechnique
  timestamp: string
}

export interface AttackState {
  phase: AttackPhase
  target: string
  accessLevel: AccessLevel
  compromisedHosts: string[]
  credentials: { username: string; hash: string; source: string }[]
  attackHistory: AttackLogEntry[]
  reconResult: ReconResult | null
  vulnerabilities: Vulnerability[]
  exploitResults: ExploitResult[]
  privescResult: PrivEscResult | null
  persistenceResult: PersistenceResult | null
  lateralMovementResults: LateralMovementResult[]
  mitreMapping: MitreMapping[]
  startTime: string | null
  endTime: string | null
}

export interface AttackLogEntry {
  timestamp: string
  phase: AttackPhase
  message: string
  level: "info" | "success" | "warning" | "error"
  mitreTechnique?: MitreTechnique
}

export interface MitreMapping {
  technique: MitreTechnique
  phase: AttackPhase
  result: "success" | "failure" | "partial"
  timestamp: string
}

export interface KnowledgeBaseEntry {
  key: string
  technique: string
  exploit: string
  severity: Severity
  cvss: number
  description: string
  mitreName: string
  mitreTactic: string
  mitreDescription: string
}
