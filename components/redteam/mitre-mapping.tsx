"use client"

import { cn } from "@/lib/utils"
import type { MitreMapping } from "@/lib/redteam/types"

const TACTIC_COLORS: Record<string, string> = {
  Reconnaissance: "bg-chart-2/20 text-chart-2 border-chart-2/30",
  "Initial Access": "bg-chart-3/20 text-chart-3 border-chart-3/30",
  Execution: "bg-chart-5/20 text-chart-5 border-chart-5/30",
  "Privilege Escalation": "bg-destructive/20 text-destructive border-destructive/30",
  Persistence: "bg-primary/20 text-primary border-primary/30",
  "Lateral Movement": "bg-chart-2/20 text-chart-2 border-chart-2/30",
  "Credential Access": "bg-chart-3/20 text-chart-3 border-chart-3/30",
}

export function MitreMappingView({
  mappings,
}: {
  mappings: MitreMapping[]
}) {
  if (mappings.length === 0) {
    return (
      <div className="rounded-lg border bg-card p-6">
        <p className="text-center font-mono text-sm text-muted-foreground">
          No MITRE ATT&CK techniques mapped yet.
        </p>
      </div>
    )
  }

  // Group by tactic
  const grouped = mappings.reduce(
    (acc, mapping) => {
      const tactic = mapping.technique.tactic
      if (!acc[tactic]) acc[tactic] = []
      acc[tactic].push(mapping)
      return acc
    },
    {} as Record<string, MitreMapping[]>
  )

  return (
    <div className="flex flex-col gap-4">
      {Object.entries(grouped).map(([tactic, items]) => (
        <div key={tactic} className="rounded-lg border bg-card p-4">
          <h4 className="mb-3 font-mono text-xs uppercase tracking-wider text-muted-foreground">
            {tactic}
          </h4>
          <div className="flex flex-wrap gap-2">
            {items.map((item, index) => (
              <div
                key={`${item.technique.id}-${index}`}
                className={cn(
                  "flex flex-col gap-1 rounded-md border p-3",
                  TACTIC_COLORS[tactic] || "bg-secondary text-foreground border-border"
                )}
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold">
                    {item.technique.id}
                  </span>
                  <span
                    className={cn(
                      "h-1.5 w-1.5 rounded-full",
                      item.result === "success" && "bg-primary",
                      item.result === "failure" && "bg-destructive",
                      item.result === "partial" && "bg-chart-3"
                    )}
                  />
                </div>
                <span className="text-[10px] opacity-80">
                  {item.technique.name}
                </span>
                <span className="font-mono text-[9px] uppercase opacity-60">
                  {item.result}
                </span>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}
