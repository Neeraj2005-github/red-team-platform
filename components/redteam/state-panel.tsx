"use client"

import { cn } from "@/lib/utils"
import type { AttackState } from "@/lib/redteam/types"
import {
  Shield,
  Server,
  Key,
  Activity,
  Clock,
  Target,
} from "lucide-react"

function StatCard({
  icon: Icon,
  label,
  value,
  variant = "default",
}: {
  icon: React.ComponentType<{ className?: string }>
  label: string
  value: string | number
  variant?: "default" | "success" | "danger" | "warning"
}) {
  return (
    <div className="flex items-center gap-3 rounded-lg border bg-card p-3">
      <div
        className={cn(
          "flex h-9 w-9 shrink-0 items-center justify-center rounded-md",
          variant === "success" && "bg-primary/10 text-primary",
          variant === "danger" && "bg-destructive/10 text-destructive",
          variant === "warning" && "bg-chart-3/10 text-chart-3",
          variant === "default" && "bg-secondary text-muted-foreground"
        )}
      >
        <Icon className="h-4 w-4" />
      </div>
      <div className="min-w-0">
        <p className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
          {label}
        </p>
        <p
          className={cn(
            "text-sm font-semibold font-mono truncate",
            variant === "success" && "text-primary",
            variant === "danger" && "text-destructive",
            variant === "warning" && "text-chart-3",
            variant === "default" && "text-foreground"
          )}
        >
          {value}
        </p>
      </div>
    </div>
  )
}

export function StatePanel({
  state,
  summary,
}: {
  state: AttackState | null
  summary: {
    target?: string
    finalAccessLevel?: string
    compromisedHosts?: string[]
    credentialsObtained?: number
    vulnerabilitiesFound?: number
    successfulExploits?: number
    mitreTechniquesUsed?: string[]
  } | null
}) {
  const accessLevel = summary?.finalAccessLevel || state?.accessLevel || "none"
  const compromised = summary?.compromisedHosts?.length || state?.compromisedHosts.length || 0
  const creds = summary?.credentialsObtained || state?.credentials.length || 0
  const vulns = summary?.vulnerabilitiesFound || state?.vulnerabilities.length || 0
  const techniques = summary?.mitreTechniquesUsed?.length || state?.mitreMapping.length || 0

  return (
    <div className="flex flex-col gap-3">
      <h3 className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
        Operation Status
      </h3>
      <div className="grid grid-cols-2 gap-2 lg:grid-cols-3">
        <StatCard
          icon={Target}
          label="Target"
          value={summary?.target || state?.target || "N/A"}
          variant="default"
        />
        <StatCard
          icon={Shield}
          label="Access Level"
          value={accessLevel.toUpperCase()}
          variant={
            accessLevel === "root" || accessLevel === "admin"
              ? "success"
              : accessLevel === "user"
                ? "warning"
                : "danger"
          }
        />
        <StatCard
          icon={Server}
          label="Compromised"
          value={`${compromised} host${compromised !== 1 ? "s" : ""}`}
          variant={compromised > 0 ? "success" : "default"}
        />
        <StatCard
          icon={Key}
          label="Credentials"
          value={creds}
          variant={creds > 0 ? "warning" : "default"}
        />
        <StatCard
          icon={Activity}
          label="Vulns Found"
          value={vulns}
          variant={vulns > 0 ? "danger" : "default"}
        />
        <StatCard
          icon={Clock}
          label="Techniques"
          value={techniques}
          variant="default"
        />
      </div>
    </div>
  )
}
