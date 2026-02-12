"use client"

import { useState, useCallback } from "react"
import { cn } from "@/lib/utils"
import type {
  AttackPhase,
  AttackState,
  AttackLogEntry,
  MitreMapping,
  Vulnerability,
} from "@/lib/redteam/types"
import { AttackChain } from "./attack-chain"
import { TerminalLog } from "./terminal-log"
import { StatePanel } from "./state-panel"
import { VulnerabilityTable } from "./vulnerability-table"
import { MitreMappingView } from "./mitre-mapping"
import { ReportView } from "./report-view"
import { Button } from "@/components/ui/button"
import {
  Play,
  RotateCcw,
  Terminal,
  ShieldAlert,
  Map,
  FileText,
  Crosshair,
  Loader2,
} from "lucide-react"

type TabId = "terminal" | "vulnerabilities" | "mitre" | "report"

const PHASES_SEQUENCE: AttackPhase[] = [
  "recon",
  "scanning",
  "analysis",
  "exploitation",
  "privilege_escalation",
  "persistence",
  "lateral_movement",
  "reporting",
  "complete",
]

export function Dashboard() {
  const [target, setTarget] = useState("")
  const [isRunning, setIsRunning] = useState(false)
  const [currentPhase, setCurrentPhase] = useState<AttackPhase>("idle")
  const [logs, setLogs] = useState<AttackLogEntry[]>([])
  const [state, setState] = useState<AttackState | null>(null)
  const [summary, setSummary] = useState<{
    target: string
    startTime: string
    endTime: string
    finalAccessLevel: string
    compromisedHosts: string[]
    credentialsObtained: number
    vulnerabilitiesFound: number
    exploitsAttempted: number
    successfulExploits: number
    persistenceEstablished: boolean
    lateralMovementSuccesses: number
    mitreTechniquesUsed: string[]
  } | null>(null)
  const [mitreMapping, setMitreMapping] = useState<MitreMapping[]>([])
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([])
  const [activeTab, setActiveTab] = useState<TabId>("terminal")

  const simulatePhaseProgression = useCallback(
    async (allLogs: AttackLogEntry[]) => {
      // Group logs by phase
      const phases: Record<string, AttackLogEntry[]> = {}
      let currentP = ""
      for (const log of allLogs) {
        if (log.message.startsWith("===")) {
          // Extract phase from the message
          currentP = log.phase
        }
        if (!phases[currentP]) phases[currentP] = []
        phases[currentP].push(log)
      }

      const displayedLogs: AttackLogEntry[] = []

      for (const phase of PHASES_SEQUENCE) {
        if (phase === "complete") break
        setCurrentPhase(phase)

        const phaseLogs = allLogs.filter((l) => l.phase === phase)
        for (const log of phaseLogs) {
          displayedLogs.push(log)
          setLogs([...displayedLogs])
          // Variable delay for more realistic feel
          const delay = log.message.startsWith("===")
            ? 400
            : log.level === "success"
              ? 200
              : 80
          await new Promise((r) => setTimeout(r, delay))
        }
      }

      // Add reporting logs
      const reportLogs = allLogs.filter((l) => l.phase === "reporting")
      for (const log of reportLogs) {
        displayedLogs.push(log)
        setLogs([...displayedLogs])
        await new Promise((r) => setTimeout(r, 200))
      }

      setCurrentPhase("complete")
    },
    []
  )

  const runSimulation = useCallback(async () => {
    if (!target.trim()) return
    setIsRunning(true)
    setLogs([])
    setState(null)
    setSummary(null)
    setMitreMapping([])
    setVulnerabilities([])
    setCurrentPhase("recon")
    setActiveTab("terminal")

    try {
      const res = await fetch("/api/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: target.trim() }),
      })

      if (!res.ok) {
        const errorData = await res.json()
        setLogs([
          {
            timestamp: new Date().toISOString(),
            phase: "recon",
            message: `Error: ${errorData.error || "Simulation failed"}`,
            level: "error",
          },
        ])
        setCurrentPhase("idle")
        setIsRunning(false)
        return
      }

      const data = await res.json()

      // Animate log display
      await simulatePhaseProgression(data.logs)

      setState(data.state)
      setSummary(data.summary)
      setMitreMapping(data.mitreMapping)
      setVulnerabilities(data.state.vulnerabilities)
    } catch {
      setLogs([
        {
          timestamp: new Date().toISOString(),
          phase: "recon",
          message: "Network error: Could not reach simulation server.",
          level: "error",
        },
      ])
      setCurrentPhase("idle")
    }
    setIsRunning(false)
  }, [target, simulatePhaseProgression])

  const resetSimulation = useCallback(() => {
    setIsRunning(false)
    setCurrentPhase("idle")
    setLogs([])
    setState(null)
    setSummary(null)
    setMitreMapping([])
    setVulnerabilities([])
  }, [])

  const tabs: { id: TabId; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { id: "terminal", label: "Terminal", icon: Terminal },
    { id: "vulnerabilities", label: "Vulnerabilities", icon: ShieldAlert },
    { id: "mitre", label: "MITRE ATT&CK", icon: Map },
    { id: "report", label: "Report", icon: FileText },
  ]

  return (
    <div className="flex min-h-screen flex-col bg-background">
      {/* Header */}
      <header className="border-b bg-card/50 backdrop-blur-sm">
        <div className="mx-auto flex max-w-[1400px] items-center justify-between px-6 py-3">
          <div className="flex items-center gap-3">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary">
              <Crosshair className="h-4 w-4 text-primary-foreground" />
            </div>
            <div>
              <h1 className="font-mono text-sm font-bold tracking-tight text-foreground">
                REDTEAM AI
              </h1>
              <p className="font-mono text-[10px] uppercase tracking-widest text-muted-foreground">
                Offensive Security Automation
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div
              className={cn(
                "flex items-center gap-2 rounded-md px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider",
                currentPhase === "complete"
                  ? "bg-primary/10 text-primary"
                  : currentPhase === "idle"
                    ? "bg-secondary text-muted-foreground"
                    : "bg-chart-3/10 text-chart-3"
              )}
            >
              <span
                className={cn(
                  "h-1.5 w-1.5 rounded-full",
                  currentPhase === "complete"
                    ? "bg-primary"
                    : currentPhase === "idle"
                      ? "bg-muted-foreground"
                      : "bg-chart-3 animate-pulse"
                )}
              />
              {currentPhase === "idle"
                ? "Standby"
                : currentPhase === "complete"
                  ? "Complete"
                  : `Running: ${currentPhase.replace("_", " ")}`}
            </div>
          </div>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-[1400px] flex-1 flex-col gap-6 px-6 py-6">
        {/* Target Input & Controls */}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-end">
          <div className="flex-1">
            <label className="mb-1.5 block font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
              Target IP / Network Range
            </label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <span className="absolute left-3 top-1/2 -translate-y-1/2 font-mono text-xs text-muted-foreground">
                  $
                </span>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="192.168.1.10"
                  disabled={isRunning}
                  className="h-10 w-full rounded-md border bg-secondary pl-7 pr-3 font-mono text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary disabled:opacity-50"
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !isRunning) runSimulation()
                  }}
                />
              </div>
              <Button
                onClick={runSimulation}
                disabled={isRunning || !target.trim()}
                className="gap-2 bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              >
                {isRunning ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Play className="h-4 w-4" />
                )}
                {isRunning ? "Running" : "Execute"}
              </Button>
              <Button
                onClick={resetSimulation}
                variant="outline"
                className="gap-2 border-border text-foreground hover:bg-secondary"
              >
                <RotateCcw className="h-4 w-4" />
                <span className="hidden sm:inline">Reset</span>
              </Button>
            </div>
          </div>
        </div>

        {/* Attack Chain Progress */}
        <AttackChain currentPhase={currentPhase} />

        {/* State Panel */}
        <StatePanel state={state} summary={summary} />

        {/* Tabs */}
        <div className="flex items-center gap-1 border-b">
          {tabs.map((tab) => {
            const Icon = tab.icon
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={cn(
                  "flex items-center gap-2 border-b-2 px-4 py-2.5 font-mono text-xs uppercase tracking-wider transition-colors",
                  activeTab === tab.id
                    ? "border-primary text-primary"
                    : "border-transparent text-muted-foreground hover:text-foreground"
                )}
              >
                <Icon className="h-3.5 w-3.5" />
                {tab.label}
              </button>
            )
          })}
        </div>

        {/* Tab Content */}
        <div className="flex-1 pb-8">
          {activeTab === "terminal" && <TerminalLog logs={logs} />}
          {activeTab === "vulnerabilities" && (
            <VulnerabilityTable vulnerabilities={vulnerabilities} />
          )}
          {activeTab === "mitre" && (
            <MitreMappingView mappings={mitreMapping} />
          )}
          {activeTab === "report" && (
            <ReportView
              state={state}
              summary={summary}
              mitreMapping={mitreMapping}
            />
          )}
        </div>
      </main>
    </div>
  )
}
