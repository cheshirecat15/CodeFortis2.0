import { Badge } from "@/components/ui/badge";
import {
  AlertOctagon,
  AlertTriangle,
  BookOpen,
  CheckSquare,
  ChevronDown,
  ChevronUp,
  Code2,
  Crosshair,
  Eye,
  Info,
  ListChecks,
  ShieldAlert,
  Square,
  Target,
  Wrench,
  Zap,
} from "lucide-react";
import { useState } from "react";
import type { AnalysisMode, Finding } from "../types/findings";

interface FindingCardProps {
  finding: Finding;
  mode: AnalysisMode;
  index: number;
}

function SeverityBadge({ severity }: { severity: Finding["severity"] }) {
  if (severity === "high") {
    return (
      <span
        className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold font-mono"
        style={{
          background: "oklch(0.55 0.22 25 / 0.10)",
          color: "oklch(0.45 0.22 25)",
          border: "1px solid oklch(0.55 0.22 25 / 0.3)",
        }}
      >
        <ShieldAlert className="w-3 h-3" />
        HIGH
      </span>
    );
  }
  if (severity === "medium") {
    return (
      <span
        className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold font-mono"
        style={{
          background: "oklch(0.65 0.18 65 / 0.10)",
          color: "oklch(0.50 0.18 65)",
          border: "1px solid oklch(0.65 0.18 65 / 0.3)",
        }}
      >
        <AlertTriangle className="w-3 h-3" />
        MEDIUM
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-bold font-mono"
      style={{
        background: "oklch(0.52 0.18 240 / 0.10)",
        color: "oklch(0.40 0.18 240)",
        border: "1px solid oklch(0.52 0.18 240 / 0.3)",
      }}
    >
      <Info className="w-3 h-3" />
      LOW
    </span>
  );
}

function ChecklistItem({
  text,
  accentColor,
}: { text: string; accentColor: string }) {
  const [checked, setChecked] = useState(false);
  const toggle = () => setChecked((c) => !c);
  return (
    <li className="flex items-start gap-2">
      <button
        type="button"
        className="flex items-start gap-2 cursor-pointer text-left w-full"
        onClick={toggle}
      >
        {checked ? (
          <CheckSquare
            className="w-4 h-4 shrink-0 mt-0.5"
            style={{ color: accentColor }}
          />
        ) : (
          <Square
            className="w-4 h-4 shrink-0 mt-0.5 transition-colors"
            style={{ color: "oklch(0.65 0.02 250)" }}
          />
        )}
        <span
          className="text-sm leading-relaxed transition-colors font-mono"
          style={{
            color: checked ? "oklch(0.70 0.02 250)" : "oklch(0.25 0.02 250)",
            textDecoration: checked ? "line-through" : "none",
          }}
        >
          {text}
        </span>
      </button>
    </li>
  );
}

export function FindingCard({ finding, mode, index }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false);

  const isDeveloper = mode === "developer";

  const modeAccent = isDeveloper
    ? "oklch(0.48 0.20 240)"
    : "oklch(0.45 0.22 25)";
  const modeAccentDim = isDeveloper
    ? "oklch(0.48 0.20 240 / 0.25)"
    : "oklch(0.45 0.22 25 / 0.25)";
  const modeAccentBg = isDeveloper
    ? "oklch(0.48 0.20 240 / 0.06)"
    : "oklch(0.45 0.22 25 / 0.06)";

  const borderLeftColor =
    finding.severity === "high"
      ? "oklch(0.55 0.22 25)"
      : finding.severity === "medium"
        ? "oklch(0.65 0.18 65)"
        : "oklch(0.52 0.18 240)";

  return (
    <div
      data-ocid={`findings.item.${index + 1}`}
      className="rounded-lg overflow-hidden transition-shadow duration-200 hover:shadow-card-hover"
      style={{
        background: "oklch(var(--card))",
        border: "1px solid oklch(var(--border))",
        borderLeft: `3px solid ${borderLeftColor}`,
        boxShadow: "0 1px 3px rgba(0,0,0,0.06)",
      }}
    >
      {/* Header — always visible */}
      <button
        type="button"
        className="w-full text-left p-4 flex items-start gap-3 transition-colors duration-150 hover:bg-muted/40"
        style={{ background: "transparent" }}
        onClick={() => setExpanded(!expanded)}
        aria-expanded={expanded}
      >
        <span
          className="text-xs font-mono mt-0.5 shrink-0 w-6"
          style={{ color: "oklch(0.65 0.02 250)" }}
        >
          #{index + 1}
        </span>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2 mb-1.5">
            <SeverityBadge severity={finding.severity} />
            <Badge
              variant="outline"
              className="text-xs font-mono"
              style={{
                border: "1px solid oklch(var(--border))",
                color: "oklch(0.50 0.03 250)",
                background: "transparent",
              }}
            >
              {finding.ruleId}
            </Badge>
            <span
              className="text-xs font-mono px-1.5 py-0.5 rounded hidden sm:inline-flex items-center gap-1"
              style={{
                background: modeAccentBg,
                color: modeAccent,
                border: `1px solid ${modeAccentDim}`,
                fontSize: "0.65rem",
                letterSpacing: "0.05em",
              }}
            >
              {isDeveloper ? (
                <>
                  <Zap className="w-2.5 h-2.5" />
                  DEV
                </>
              ) : (
                <>
                  <Target className="w-2.5 h-2.5" />
                  RECON
                </>
              )}
            </span>
            <span
              className="text-xs font-mono hidden sm:block"
              style={{ color: "oklch(0.55 0.03 250)" }}
            >
              Line {finding.lineNumber}
            </span>
          </div>
          <p
            className="text-sm font-semibold mb-1"
            style={{ color: "oklch(0.15 0.02 250)" }}
          >
            {finding.ruleName}
          </p>
          <p
            className="text-xs truncate font-mono"
            style={{ color: "oklch(0.50 0.03 250)" }}
          >
            {finding.owaspCategory}
          </p>
          <div className="mt-2 flex items-center gap-2">
            <Code2
              className="w-3.5 h-3.5 shrink-0"
              style={{ color: "oklch(0.60 0.03 250)" }}
            />
            <code
              className="text-xs font-mono px-2 py-0.5 rounded truncate max-w-full"
              style={{
                color: "oklch(0.30 0.10 250)",
                background: "oklch(0.94 0.008 240)",
                border: "1px solid oklch(0.88 0.01 240)",
              }}
            >
              L{finding.lineNumber}: {finding.matchedText.slice(0, 80)}
              {finding.matchedText.length > 80 ? "…" : ""}
            </code>
          </div>
        </div>
        <div
          className="shrink-0 mt-0.5"
          style={{ color: "oklch(0.60 0.02 250)" }}
        >
          {expanded ? (
            <ChevronUp className="w-4 h-4" />
          ) : (
            <ChevronDown className="w-4 h-4" />
          )}
        </div>
      </button>

      {/* Expanded content */}
      {expanded && (
        <div
          className="px-4 pb-4 pt-4 space-y-4"
          style={{ borderTop: `1px solid ${modeAccentDim}` }}
        >
          {isDeveloper ? (
            <>
              <div
                className="flex items-center gap-2 px-3 py-1.5 rounded mb-2"
                style={{
                  background: "oklch(0.48 0.20 240 / 0.06)",
                  border: "1px solid oklch(0.48 0.20 240 / 0.2)",
                }}
              >
                <Zap
                  className="w-3 h-3"
                  style={{ color: "oklch(0.48 0.20 240)" }}
                />
                <span
                  className="text-xs font-mono tracking-wider uppercase font-semibold"
                  style={{ color: "oklch(0.40 0.20 240)" }}
                >
                  Developer Analysis — Secure Code Guidance
                </span>
              </div>

              <Section
                icon={
                  <BookOpen
                    className="w-4 h-4"
                    style={{ color: "oklch(0.48 0.20 240)" }}
                  />
                }
                title="Why is this insecure?"
                titleColor="oklch(0.40 0.20 240)"
                content={finding.developerExplanation}
              />
              <Section
                icon={
                  <ShieldAlert
                    className="w-4 h-4"
                    style={{ color: "oklch(0.45 0.22 25)" }}
                  />
                }
                title="Real-World Threat Scenario"
                titleColor="oklch(0.45 0.22 25)"
                content={finding.threatScenario}
              />

              <div>
                <div className="flex items-center gap-2 mb-2">
                  <Code2
                    className="w-4 h-4"
                    style={{ color: "oklch(0.48 0.20 145)" }}
                  />
                  <span
                    className="text-xs font-semibold uppercase tracking-wider font-mono"
                    style={{ color: "oklch(0.38 0.18 145)" }}
                  >
                    Secure Alternative
                  </span>
                </div>
                <div
                  className="rounded-lg p-3"
                  style={{
                    background: "oklch(0.48 0.20 145 / 0.05)",
                    border: "1px solid oklch(0.48 0.20 145 / 0.2)",
                  }}
                >
                  <p
                    className="text-sm leading-relaxed font-mono"
                    style={{ color: "oklch(0.20 0.02 250)" }}
                  >
                    {finding.secureAlternative}
                  </p>
                </div>
              </div>

              {finding.suggestedFix && (
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <Wrench
                      className="w-4 h-4"
                      style={{ color: "oklch(0.48 0.20 240)" }}
                    />
                    <span
                      className="text-xs font-semibold uppercase tracking-wider font-mono"
                      style={{ color: "oklch(0.40 0.20 240)" }}
                    >
                      Suggested Fix
                    </span>
                  </div>
                  <div
                    className="rounded-lg p-3 overflow-x-auto"
                    style={{
                      background: "oklch(0.94 0.008 240)",
                      border: "1px solid oklch(0.88 0.01 240)",
                    }}
                  >
                    <pre
                      className="text-xs font-mono leading-relaxed whitespace-pre"
                      style={{ color: "oklch(0.20 0.02 250)" }}
                    >
                      {finding.suggestedFix}
                    </pre>
                  </div>
                </div>
              )}
            </>
          ) : (
            <>
              <div
                className="flex items-center gap-2 px-3 py-1.5 rounded mb-2"
                style={{
                  background: "oklch(0.55 0.22 25 / 0.05)",
                  border: "1px solid oklch(0.55 0.22 25 / 0.2)",
                }}
              >
                <Target
                  className="w-3 h-3"
                  style={{ color: "oklch(0.45 0.22 25)" }}
                />
                <span
                  className="text-xs font-mono tracking-wider uppercase font-semibold"
                  style={{ color: "oklch(0.40 0.20 25)" }}
                >
                  Threat Intel — Attacker Mindset
                </span>
              </div>

              <Section
                icon={
                  <Crosshair
                    className="w-4 h-4"
                    style={{ color: "oklch(0.45 0.22 25)" }}
                  />
                }
                title="Attacker Perspective"
                titleColor="oklch(0.40 0.20 25)"
                content={finding.attackerPerspective}
              />
              <Section
                icon={
                  <Eye
                    className="w-4 h-4"
                    style={{ color: "oklch(0.45 0.22 25)" }}
                  />
                }
                title="Exploitation Reasoning"
                titleColor="oklch(0.40 0.20 25)"
                content={finding.exploitationReasoning}
              />
              <Section
                icon={
                  <AlertOctagon
                    className="w-4 h-4"
                    style={{ color: "oklch(0.45 0.22 25)" }}
                  />
                }
                title="Impact Assessment"
                titleColor="oklch(0.40 0.18 25)"
                content={finding.impactAnalysis}
              />
              <Section
                icon={
                  <AlertTriangle
                    className="w-4 h-4"
                    style={{ color: "oklch(0.50 0.18 65)" }}
                  />
                }
                title="Bypass Considerations"
                titleColor="oklch(0.45 0.16 65)"
                content={finding.bypassConsiderations}
              />

              <div>
                <div
                  className="flex items-center gap-2 mb-3 px-3 py-1.5 rounded"
                  style={{
                    background: "oklch(0.55 0.22 25 / 0.05)",
                    border: "1px solid oklch(0.55 0.22 25 / 0.15)",
                  }}
                >
                  <ListChecks
                    className="w-4 h-4"
                    style={{ color: "oklch(0.45 0.22 25)" }}
                  />
                  <span
                    className="text-xs font-semibold uppercase tracking-wider font-mono"
                    style={{ color: "oklch(0.40 0.20 25)" }}
                  >
                    Manual Verification Checklist
                  </span>
                </div>
                <ul className="space-y-2 pl-1">
                  {finding.manualVerificationChecklist.map((item) => (
                    <ChecklistItem
                      key={item}
                      text={item}
                      accentColor="oklch(0.45 0.22 25)"
                    />
                  ))}
                </ul>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function Section({
  icon,
  title,
  titleColor,
  content,
}: {
  icon: React.ReactNode;
  title: string;
  titleColor: string;
  content: string;
  accentColor?: string;
}) {
  return (
    <div>
      <div className="flex items-center gap-2 mb-1.5">
        {icon}
        <span
          className="text-xs font-semibold uppercase tracking-wider font-mono"
          style={{ color: titleColor }}
        >
          {title}
        </span>
      </div>
      <p
        className="text-sm leading-relaxed pl-6 font-mono"
        style={{ color: "oklch(0.30 0.02 250)" }}
      >
        {content}
      </p>
    </div>
  );
}
