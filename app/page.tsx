"use client"

import dynamic from "next/dynamic"

const Dashboard = dynamic(
  () => import("@/components/redteam/dashboard").then((mod) => mod.Dashboard),
  {
    ssr: false,
    loading: () => (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-4">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          <p className="font-mono text-sm text-muted-foreground">
            Initializing RedTeam AI...
          </p>
        </div>
      </div>
    ),
  }
)

export default function Page() {
  return <Dashboard />
}
