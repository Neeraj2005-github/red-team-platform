"use client"

import { cn } from "@/lib/utils"
import type { AttackState, MitreMapping } from "@/lib/redteam/types"
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Download,
} from "lucide-react"
import { Button } from "@/components/ui/button"

interface ReportSummary {
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
}

function StatusIndicator({ success }: { success: boolean }) {
  return success ? (
    <CheckCircle2 className="h-4 w-4 text-primary" />
  ) : (
    <XCircle className="h-4 w-4 text-destructive" />
  )
}

export function ReportView({
  state,
  summary,
  mitreMapping,
}: {
  state: AttackState | null
  summary: ReportSummary | null
  mitreMapping: MitreMapping[]
}) {
  if (!summary || !state) {
    return (
      <div className="rounded-lg border bg-card p-8">
        <p className="text-center font-mono text-sm text-muted-foreground">
          Run a simulation to generate the attack report.
        </p>
      </div>
    )
  }

  const compromiseStatus =
    summary.finalAccessLevel === "root" || summary.finalAccessLevel === "admin"
      ? "FULL COMPROMISE"
      : summary.finalAccessLevel === "user"
        ? "PARTIAL COMPROMISE"
        : "NO ACCESS GAINED"

  const reportJSON = JSON.stringify(
    {
      report: {
        title: "Red Team Attack Simulation Report",
        target: summary.target,
        executionTime: {
          start: summary.startTime,
          end: summary.endTime,
        },
        results: {
          finalAccessLevel: summary.finalAccessLevel,
          compromiseStatus,
          compromisedHosts: summary.compromisedHosts,
          credentialsObtained: summary.credentialsObtained,
        },
        subdomains: state.reconResult?.subdomains?.filter((s) => s.status === "alive").map((s) => ({
          subdomain: s.subdomain,
          ip: s.ip,
        })) || [],
        vulnerabilities: state.vulnerabilities.map((v) => ({
          id: v.id,
          name: v.name,
          severity: v.severity,
          cvss: v.cvss,
          port: v.port,
          mitre: v.mitreTechnique.id,
        })),
        attackPath: mitreMapping.map((m) => ({
          technique: m.technique.id,
          name: m.technique.name,
          tactic: m.technique.tactic,
          result: m.result,
        })),
        mitreTechniques: summary.mitreTechniquesUsed,
      },
    },
    null,
    2
  )

  function downloadFile(content: string, filename: string, type: string) {
    const blob = new Blob([content], { type })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  function downloadJSON() {
    downloadFile(
      reportJSON,
      `redteam-report-${summary.target.replace(/\./g, "_")}.json`,
      "application/json"
    )
  }

  function downloadCSV() {
    const header = "CVE,Name,Severity,CVSS,Port,MITRE Technique\n"
    const rows = state.vulnerabilities
      .map(
        (v) =>
          `"${v.id}","${v.name}","${v.severity}",${v.cvss},${v.port},"${v.mitreTechnique.id}"`
      )
      .join("\n")
    downloadFile(
      header + rows,
      `redteam-vulns-${summary.target.replace(/\./g, "_")}.csv`,
      "text/csv"
    )
  }

  function downloadText() {
    const divider = "=".repeat(60)
    const lines = [
      divider,
      "  RED TEAM ATTACK SIMULATION REPORT",
      divider,
      "",
      `Target:              ${summary.target}`,
      `Start Time:          ${new Date(summary.startTime).toLocaleString()}`,
      `End Time:            ${new Date(summary.endTime).toLocaleString()}`,
      `Compromise Status:   ${compromiseStatus}`,
      `Final Access Level:  ${summary.finalAccessLevel.toUpperCase()}`,
      "",
      "-".repeat(60),
      "  RESULTS SUMMARY",
      "-".repeat(60),
      "",
      `Vulnerabilities Found:     ${summary.vulnerabilitiesFound}`,
      `Exploits Attempted:        ${summary.exploitsAttempted}`,
      `Successful Exploits:       ${summary.successfulExploits}`,
      `Credentials Obtained:      ${summary.credentialsObtained}`,
      `Persistence Established:   ${summary.persistenceEstablished ? "Yes" : "No"}`,
      `Lateral Movement Successes: ${summary.lateralMovementSuccesses}`,
      `Compromised Hosts:         ${summary.compromisedHosts.join(", ")}`,
      "",
      "-".repeat(60),
      "  DISCOVERED SUBDOMAINS",
      "-".repeat(60),
      "",
      ...(state.reconResult?.subdomains?.filter((s) => s.status === "alive").map(
        (s) => `[ALIVE] ${s.subdomain} -> ${s.ip}`
      ) || ["  No subdomains discovered"]),
      "",
      "-".repeat(60),
      "  VULNERABILITIES",
      "-".repeat(60),
      "",
      ...state.vulnerabilities.map(
        (v) =>
          `[${v.severity.toUpperCase()}] ${v.id} - ${v.name} (CVSS: ${v.cvss}, Port: ${v.port})`
      ),
      "",
      "-".repeat(60),
      "  MITRE ATT&CK TECHNIQUES",
      "-".repeat(60),
      "",
      ...mitreMapping.map(
        (m) =>
          `[${m.result.toUpperCase()}] ${m.technique.id} - ${m.technique.name} (${m.technique.tactic})`
      ),
      "",
      divider,
      "  END OF REPORT",
      divider,
    ]
    downloadFile(
      lines.join("\n"),
      `redteam-report-${summary.target.replace(/\./g, "_")}.txt`,
      "text/plain"
    )
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Report Header */}
      <div className="rounded-lg border bg-card p-6">
        <div className="flex items-start justify-between">
          <div>
            <h3 className="font-mono text-lg font-bold text-foreground">
              Attack Simulation Report
            </h3>
            <p className="mt-1 font-mono text-xs text-muted-foreground">
              Target: {summary.target} | Generated:{" "}
              {new Date(summary.endTime).toLocaleString()}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              onClick={downloadJSON}
              size="sm"
              className="gap-2 bg-primary text-primary-foreground hover:bg-primary/90"
            >
              <Download className="h-3.5 w-3.5" />
              JSON
            </Button>
            <Button
              onClick={downloadCSV}
              size="sm"
              variant="outline"
              className="gap-2 border-border text-foreground hover:bg-secondary"
            >
              <Download className="h-3.5 w-3.5" />
              CSV
            </Button>
            <Button
              onClick={downloadText}
              size="sm"
              variant="outline"
              className="gap-2 border-border text-foreground hover:bg-secondary"
            >
              <Download className="h-3.5 w-3.5" />
              TXT
            </Button>
          </div>
        </div>

        {/* Compromise Status Banner */}
        <div
          className={cn(
            "mt-4 flex items-center gap-3 rounded-md border p-4",
            compromiseStatus === "FULL COMPROMISE" &&
              "border-primary/30 bg-primary/5",
            compromiseStatus === "PARTIAL COMPROMISE" &&
              "border-chart-3/30 bg-chart-3/5",
            compromiseStatus === "NO ACCESS GAINED" &&
              "border-destructive/30 bg-destructive/5"
          )}
        >
          {compromiseStatus === "FULL COMPROMISE" ? (
            <AlertTriangle className="h-5 w-5 text-primary" />
          ) : compromiseStatus === "PARTIAL COMPROMISE" ? (
            <AlertTriangle className="h-5 w-5 text-chart-3" />
          ) : (
            <CheckCircle2 className="h-5 w-5 text-destructive" />
          )}
          <div>
            <p
              className={cn(
                "font-mono text-sm font-bold",
                compromiseStatus === "FULL COMPROMISE" && "text-primary",
                compromiseStatus === "PARTIAL COMPROMISE" && "text-chart-3",
                compromiseStatus === "NO ACCESS GAINED" && "text-destructive"
              )}
            >
              {compromiseStatus}
            </p>
            <p className="font-mono text-xs text-muted-foreground">
              Final privilege level: {summary.finalAccessLevel.toUpperCase()}
            </p>
          </div>
        </div>
      </div>

      {/* Results Grid */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          {
            label: "Vulnerabilities",
            value: summary.vulnerabilitiesFound,
            success: summary.vulnerabilitiesFound > 0,
          },
          {
            label: "Exploits Attempted",
            value: `${summary.successfulExploits}/${summary.exploitsAttempted}`,
            success: summary.successfulExploits > 0,
          },
          {
            label: "Persistence",
            value: summary.persistenceEstablished ? "Established" : "Failed",
            success: summary.persistenceEstablished,
          },
          {
            label: "Lateral Moves",
            value: summary.lateralMovementSuccesses,
            success: summary.lateralMovementSuccesses > 0,
          },
        ].map((item) => (
          <div
            key={item.label}
            className="flex items-center gap-3 rounded-lg border bg-card p-4"
          >
            <StatusIndicator success={item.success} />
            <div>
              <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                {item.label}
              </p>
              <p className="font-mono text-sm font-bold text-foreground">
                {item.value}
              </p>
            </div>
          </div>
        ))}
      </div>

      {/* Attack Path */}
      <div className="rounded-lg border bg-card p-4">
        <h4 className="mb-3 font-mono text-xs uppercase tracking-wider text-muted-foreground">
          Attack Path
        </h4>
        <div className="flex flex-wrap items-center gap-2">
          {mitreMapping.map((mapping, index) => (
            <div key={index} className="flex items-center gap-2">
              <span
                className={cn(
                  "rounded px-2 py-1 font-mono text-[10px] font-bold",
                  mapping.result === "success" &&
                    "bg-primary/10 text-primary",
                  mapping.result === "failure" &&
                    "bg-destructive/10 text-destructive",
                  mapping.result === "partial" &&
                    "bg-chart-3/10 text-chart-3"
                )}
              >
                {mapping.technique.id}
              </span>
              {index < mitreMapping.length - 1 && (
                <span className="text-muted-foreground/30">{">"}</span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* JSON Preview */}
      <div className="rounded-lg border bg-card">
        <div className="flex items-center justify-between border-b px-4 py-2">
          <span className="font-mono text-xs text-muted-foreground">
            report.json
          </span>
        </div>
        <pre className="max-h-96 overflow-auto p-4 font-mono text-[11px] text-foreground/80">
          {reportJSON}
        </pre>
      </div>
    </div>
  )
}
