"use client"

import { useEffect, useRef } from "react"
import { cn } from "@/lib/utils"
import type { AttackLogEntry } from "@/lib/redteam/types"

function LogLine({ entry, index }: { entry: AttackLogEntry; index: number }) {
  const time = new Date(entry.timestamp).toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  })

  return (
    <div className="flex gap-2 font-mono text-xs leading-relaxed">
      <span className="shrink-0 text-muted-foreground/50">{String(index + 1).padStart(3, "0")}</span>
      <span className="shrink-0 text-muted-foreground">[{time}]</span>
      <span
        className={cn(
          "shrink-0 w-5 text-center font-bold",
          entry.level === "success" && "text-primary",
          entry.level === "warning" && "text-chart-3",
          entry.level === "error" && "text-destructive",
          entry.level === "info" && "text-chart-2"
        )}
      >
        {entry.level === "success"
          ? "+"
          : entry.level === "error"
            ? "!"
            : entry.level === "warning"
              ? "*"
              : "-"}
      </span>
      <span
        className={cn(
          entry.level === "success" && "text-primary",
          entry.level === "warning" && "text-chart-3",
          entry.level === "error" && "text-destructive",
          entry.level === "info" && "text-foreground/80",
          entry.message.startsWith("===") && "font-bold text-foreground"
        )}
      >
        {entry.message}
      </span>
      {entry.mitreTechnique && (
        <span className="shrink-0 rounded bg-primary/10 px-1.5 py-0.5 text-[10px] text-primary">
          {entry.mitreTechnique.id}
        </span>
      )}
    </div>
  )
}

export function TerminalLog({ logs }: { logs: AttackLogEntry[] }) {
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [logs])

  return (
    <div className="flex h-full flex-col rounded-lg border bg-card">
      <div className="flex items-center gap-2 border-b px-4 py-2">
        <div className="flex gap-1.5">
          <div className="h-2.5 w-2.5 rounded-full bg-destructive/80" />
          <div className="h-2.5 w-2.5 rounded-full bg-chart-3/80" />
          <div className="h-2.5 w-2.5 rounded-full bg-primary/80" />
        </div>
        <span className="font-mono text-xs text-muted-foreground">
          redteam-ai ~ attack-log
        </span>
      </div>
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto p-4"
        style={{ maxHeight: "500px" }}
      >
        {logs.length === 0 ? (
          <div className="flex items-center gap-2 font-mono text-xs text-muted-foreground">
            <span>root@redteam-ai:~$</span>
            <span className="cursor-blink">_</span>
          </div>
        ) : (
          <div className="flex flex-col gap-0.5">
            {logs.map((entry, index) => (
              <LogLine key={index} entry={entry} index={index} />
            ))}
            <div className="mt-1 flex items-center gap-2 font-mono text-xs text-muted-foreground">
              <span>root@redteam-ai:~$</span>
              <span className="cursor-blink">_</span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
