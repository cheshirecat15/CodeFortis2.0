import { ShieldCheck } from "lucide-react";
import type { AnalysisMode, Finding } from "../types/findings";
import { FindingCard } from "./FindingCard";

interface ResultsPanelProps {
  findings: Finding[];
  mode: AnalysisMode;
  onModeChange: (mode: AnalysisMode) => void;
}

export function ResultsPanel({
  findings,
  mode,
  onModeChange,
}: ResultsPanelProps) {
  const isDeveloper = mode === "developer";

  const devAccent = "oklch(0.48 0.20 240)";
  const bugAccent = "oklch(0.45 0.22 25)";
  const activeAccent = isDeveloper ? devAccent : bugAccent;
  const activeBg = isDeveloper
    ? "oklch(0.48 0.20 240 / 0.06)"
    : "oklch(0.45 0.22 25 / 0.06)";
  const activeBorder = isDeveloper
    ? "oklch(0.48 0.20 240 / 0.25)"
    : "oklch(0.45 0.22 25 / 0.25)";

  return (
    <div>
      {/* Mode selector tabs */}
      <div className="flex gap-2 mb-5">
        <button
          type="button"
          data-ocid="results.tab"
          onClick={() => onModeChange("developer")}
          className="flex-1 px-4 py-2.5 rounded-lg text-sm font-semibold transition-all duration-200"
          style={{
            background: isDeveloper ? activeBg : "transparent",
            color: isDeveloper ? devAccent : "oklch(0.55 0.03 250)",
            border: `1px solid ${isDeveloper ? activeBorder : "oklch(var(--border))"}`,
          }}
        >
          🔧 Developer Mode
        </button>
        <button
          type="button"
          data-ocid="results.tab"
          onClick={() => onModeChange("bugbounty")}
          className="flex-1 px-4 py-2.5 rounded-lg text-sm font-semibold transition-all duration-200"
          style={{
            background: !isDeveloper
              ? "oklch(0.45 0.22 25 / 0.06)"
              : "transparent",
            color: !isDeveloper ? bugAccent : "oklch(0.55 0.03 250)",
            border: `1px solid ${!isDeveloper ? "oklch(0.45 0.22 25 / 0.25)" : "oklch(var(--border))"}`,
          }}
        >
          🎯 Bug Bounty Mode
        </button>
      </div>

      {/* Workspace content */}
      {findings.length === 0 ? (
        <div
          data-ocid="results.empty_state"
          className="flex flex-col items-center justify-center py-14 text-center rounded-lg"
          style={{
            background: "oklch(0.98 0.003 240)",
            border: `1px solid ${activeBorder}`,
          }}
        >
          <div
            className="w-14 h-14 rounded-full flex items-center justify-center mb-4"
            style={{
              background: activeBg,
              border: `1px solid ${activeBorder}`,
            }}
          >
            <ShieldCheck className="w-7 h-7" style={{ color: activeAccent }} />
          </div>
          <h3
            className="text-base font-semibold mb-2"
            style={{ color: "oklch(0.15 0.02 250)" }}
          >
            No Vulnerabilities Detected
          </h3>
          <p
            className="text-sm max-w-sm font-mono"
            style={{ color: "oklch(0.55 0.03 250)" }}
          >
            {isDeveloper
              ? "No vulnerable patterns found. Your code appears secure for the selected categories."
              : "No attack surface identified. No risky logic patterns detected."}
          </p>
        </div>
      ) : (
        <div>
          <div
            className="flex items-center justify-between mb-3 px-3 py-2 rounded-lg"
            style={{
              background: activeBg,
              border: `1px solid ${activeBorder}`,
            }}
          >
            <span
              className="text-xs font-semibold font-mono"
              style={{ color: activeAccent }}
            >
              {isDeveloper
                ? "🔧 SECURE CODE WORKSPACE"
                : "🎯 THREAT INTEL WORKSPACE"}
            </span>
            <span
              className="text-xs font-mono"
              style={{ color: "oklch(0.55 0.03 250)" }}
            >
              {findings.length} finding{findings.length !== 1 ? "s" : ""} ·
              click to expand
            </span>
          </div>
          <div className="space-y-3">
            {findings.map((finding, i) => (
              <FindingCard
                key={`${finding.ruleId}-${finding.lineNumber}-${i}-${mode}`}
                finding={finding}
                mode={mode}
                index={i}
              />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
