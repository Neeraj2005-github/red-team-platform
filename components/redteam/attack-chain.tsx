"use client"

import { cn } from "@/lib/utils"
import type { AttackPhase } from "@/lib/redteam/types"
import {
  Search,
  Scan,
  Brain,
  Crosshair,
  ArrowUpCircle,
  Anchor,
  Move,
  FileText,
} from "lucide-react"

const PHASES: {
  id: AttackPhase
  label: string
  icon: React.ComponentType<{ className?: string }>
}[] = [
  { id: "recon", label: "Recon", icon: Search },
  { id: "scanning", label: "Scan", icon: Scan },
  { id: "analysis", label: "Analyze", icon: Brain },
  { id: "exploitation", label: "Exploit", icon: Crosshair },
  { id: "privilege_escalation", label: "PrivEsc", icon: ArrowUpCircle },
  { id: "persistence", label: "Persist", icon: Anchor },
  { id: "lateral_movement", label: "Lateral", icon: Move },
  { id: "reporting", label: "Report", icon: FileText },
]

const PHASE_ORDER: AttackPhase[] = [
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

function getPhaseStatus(
  phase: AttackPhase,
  currentPhase: AttackPhase
): "pending" | "active" | "complete" {
  const currentIndex = PHASE_ORDER.indexOf(currentPhase)
  const phaseIndex = PHASE_ORDER.indexOf(phase)

  if (currentPhase === "idle") return "pending"
  if (currentPhase === "complete") return "complete"
  if (phaseIndex < currentIndex) return "complete"
  if (phaseIndex === currentIndex) return "active"
  return "pending"
}

export function AttackChain({ currentPhase }: { currentPhase: AttackPhase }) {
  return (
    <div className="flex items-center gap-1 overflow-x-auto pb-2">
      {PHASES.map((phase, index) => {
        const status = getPhaseStatus(phase.id, currentPhase)
        const Icon = phase.icon

        return (
          <div key={phase.id} className="flex items-center">
            <div
              className={cn(
                "flex flex-col items-center gap-1.5 rounded-lg px-3 py-2 transition-all duration-300",
                status === "active" &&
                  "bg-primary/10 ring-1 ring-primary pulse-glow",
                status === "complete" && "bg-primary/5",
                status === "pending" && "opacity-40"
              )}
            >
              <div
                className={cn(
                  "flex h-9 w-9 items-center justify-center rounded-md transition-all",
                  status === "active" &&
                    "bg-primary text-primary-foreground",
                  status === "complete" &&
                    "bg-primary/20 text-primary",
                  status === "pending" &&
                    "bg-secondary text-muted-foreground"
                )}
              >
                <Icon className="h-4 w-4" />
              </div>
              <span
                className={cn(
                  "text-[10px] font-mono font-medium uppercase tracking-wider",
                  status === "active" && "text-primary",
                  status === "complete" && "text-primary/70",
                  status === "pending" && "text-muted-foreground"
                )}
              >
                {phase.label}
              </span>
            </div>
            {index < PHASES.length - 1 && (
              <div
                className={cn(
                  "mx-0.5 h-px w-4 transition-all",
                  status === "complete"
                    ? "bg-primary/50"
                    : "bg-border"
                )}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}
