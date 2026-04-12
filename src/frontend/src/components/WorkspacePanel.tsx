import { AlertCircle, ShieldCheck } from "lucide-react";
import type { Finding } from "../types/findings";
import type { OWASPCategory, SupportedLanguage } from "../types/rules";
import type { checkSyntax } from "../utils/syntaxChecker";
import { FindingCard } from "./FindingCard";
import { FixedCodePanel } from "./FixedCodePanel";
import { SummaryPanel } from "./SummaryPanel";
import { SyntaxErrorBanner } from "./SyntaxErrorBanner";

export interface WorkspacePanelProps {
  mode: "developer" | "bugbounty" | "scanner";
  /** Shared inputs — read-only, owned by AnalyzerPage */
  code: string;
  language: SupportedLanguage;
  selectedCategories: OWASPCategory[];
  /** Shared analysis results — owned by AnalyzerPage */
  findings: Finding[];
  fixedCode: string;
  analysisState: "idle" | "analyzing" | "done";
  hasAnalyzed: boolean;
  langMismatch: string | null;
  syntaxErrors: ReturnType<typeof checkSyntax>["errors"];
  onSyntaxErrorsDismiss: () => void;
}

function getModeConfig(mode: "developer" | "bugbounty" | "scanner") {
  if (mode === "developer") {
    return {
      label: "Developer Mode",
      accent: "oklch(0.48 0.20 240)",
      accentBg: "oklch(0.48 0.20 240 / 0.06)",
      accentBorder: "oklch(0.48 0.20 240 / 0.2)",
      description:
        "Educational analysis with secure coding guidance, threat scenarios, and fix suggestions.",
    };
  }
  if (mode === "bugbounty") {
    return {
      label: "Bug Bounty Mode",
      accent: "oklch(0.45 0.22 25)",
      accentBg: "oklch(0.45 0.22 25 / 0.05)",
      accentBorder: "oklch(0.45 0.22 25 / 0.2)",
      description:
        "Attacker-mindset analysis: exploitation reasoning, impact assessment, and manual verification checklists. No fix suggestions.",
    };
  }
  return {
    label: "Scanner",
    accent: "oklch(0.48 0.20 145)",
    accentBg: "oklch(0.48 0.20 145 / 0.05)",
    accentBorder: "oklch(0.48 0.20 145 / 0.15)",
    description:
      "Auto-remediation mode — produces a secure version of your code with all detected vulnerabilities fixed.",
  };
}

export function WorkspacePanel({
  mode,
  language,
  selectedCategories,
  findings,
  fixedCode,
  analysisState,
  hasAnalyzed,
  langMismatch,
  syntaxErrors,
  onSyntaxErrorsDismiss,
}: WorkspacePanelProps) {
  const config = getModeConfig(mode);
  const isAnalyzing = analysisState === "analyzing";

  // Dispatch custom event to load code into shared editor (used by FixedCodePanel)
  const handleLoadIntoEditor = (newCode: string) => {
    window.dispatchEvent(
      new CustomEvent("codefortis:load-example", { detail: { code: newCode } }),
    );
  };

  return (
    <div className="space-y-5">
      {/* Mode description banner */}
      <div
        className="px-4 py-3 rounded-lg"
        style={{
          background: config.accentBg,
          border: `1px solid ${config.accentBorder}`,
        }}
      >
        <p className="text-sm" style={{ color: "oklch(0.30 0.02 250)" }}>
          <span className="font-semibold" style={{ color: config.accent }}>
            {config.label}:{" "}
          </span>
          {config.description}
        </p>
      </div>

      {/* No categories warning */}
      {selectedCategories.length === 0 && (
        <div
          data-ocid="workspace.error_state"
          className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm"
          style={{
            background: "oklch(0.55 0.22 25 / 0.06)",
            border: "1px solid oklch(0.55 0.22 25 / 0.25)",
            color: "oklch(0.40 0.20 25)",
          }}
        >
          <AlertCircle
            className="w-4 h-4 shrink-0"
            style={{ color: "oklch(0.45 0.22 25)" }}
          />
          No OWASP categories selected — scan will return no results. Select at
          least one category in the shared input above.
        </div>
      )}

      {/* Language mismatch warning */}
      {langMismatch && (
        <div
          data-ocid="workspace.error_state"
          className="flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm"
          style={{
            background: "oklch(0.65 0.18 65 / 0.06)",
            border: "1px solid oklch(0.65 0.18 65 / 0.3)",
            color: "oklch(0.40 0.14 65)",
          }}
        >
          <AlertCircle
            className="w-4 h-4 shrink-0"
            style={{ color: "oklch(0.50 0.18 65)" }}
          />
          {langMismatch}
        </div>
      )}

      {/* Analyzing in-panel spinner (live mode) */}
      {isAnalyzing && (
        <div
          className="flex items-center gap-2 px-4 py-3 rounded-lg text-sm font-mono"
          data-ocid="workspace.loading_state"
          style={{
            background: "oklch(0.48 0.20 145 / 0.06)",
            border: "1px solid oklch(0.48 0.20 145 / 0.2)",
            color: "oklch(0.38 0.18 145)",
          }}
        >
          <span
            className="w-2 h-2 rounded-full inline-block animate-pulse"
            style={{ background: "oklch(0.48 0.20 145)" }}
          />
          Running analysis…
        </div>
      )}

      {/* ─────────────────── RESULTS ─────────────────── */}
      {hasAnalyzed && !isAnalyzing && (
        <div className="space-y-5" data-ocid="workspace.panel">
          {syntaxErrors.length > 0 && (
            <SyntaxErrorBanner
              errors={syntaxErrors}
              onDismiss={onSyntaxErrorsDismiss}
            />
          )}

          {/* SCANNER MODE: secure code only */}
          {mode === "scanner" && (
            <ScannerResults
              findings={findings}
              fixedCode={fixedCode}
              onLoadIntoEditor={handleLoadIntoEditor}
            />
          )}

          {/* DEVELOPER MODE: summary + finding cards, NO fixed code */}
          {mode === "developer" && (
            <>
              <SummaryPanel
                findings={findings}
                language={language}
                selectedCategories={selectedCategories}
              />
              <DeveloperResults findings={findings} />
            </>
          )}

          {/* BUG BOUNTY MODE: summary + attacker cards, no fixes */}
          {mode === "bugbounty" && (
            <>
              <SummaryPanel
                findings={findings}
                language={language}
                selectedCategories={selectedCategories}
              />
              <BugBountyResults findings={findings} />
            </>
          )}
        </div>
      )}

      {/* Initial / idle state */}
      {!hasAnalyzed && !isAnalyzing && (
        <div
          data-ocid="workspace.empty_state"
          className="p-8 text-center rounded-lg border"
          style={{
            borderStyle: "dashed",
            borderColor: "oklch(var(--border))",
            background: "oklch(0.98 0.003 240)",
          }}
        >
          <div className="flex flex-col items-center gap-3">
            <p className="text-sm" style={{ color: "oklch(0.50 0.03 250)" }}>
              Use the{" "}
              <span className="font-semibold" style={{ color: config.accent }}>
                Run Analysis
              </span>{" "}
              button above — results appear here and in all other workspaces
              simultaneously.
            </p>
            <p
              className="text-xs font-mono"
              style={{ color: "oklch(0.62 0.02 250)" }}
            >
              JavaScript · TypeScript · Python · Java · PHP · Go · C#
            </p>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Scanner Mode Results ─────────────────────────────────────────────────────
interface ScannerResultsProps {
  findings: Finding[];
  fixedCode: string;
  onLoadIntoEditor: (code: string) => void;
}

function ScannerResults({
  findings,
  fixedCode,
  onLoadIntoEditor,
}: ScannerResultsProps) {
  if (findings.length === 0) {
    return (
      <div
        data-ocid="workspace.empty_state"
        className="flex flex-col items-center py-12 text-center rounded-lg border"
        style={{
          background: "oklch(0.48 0.20 145 / 0.04)",
          border: "1px solid oklch(0.48 0.20 145 / 0.25)",
        }}
      >
        <div
          className="w-14 h-14 rounded-full flex items-center justify-center mb-4"
          style={{
            background: "oklch(0.48 0.20 145 / 0.12)",
            border: "1px solid oklch(0.48 0.20 145 / 0.3)",
          }}
        >
          <ShieldCheck
            className="w-7 h-7"
            style={{ color: "oklch(0.38 0.18 145)" }}
          />
        </div>
        <p
          className="text-base font-bold mb-1"
          style={{ color: "oklch(0.25 0.02 250)" }}
        >
          Code is already secure — 0 vulnerabilities found
        </p>
        <p
          className="text-sm font-mono max-w-sm"
          style={{ color: "oklch(0.50 0.03 250)" }}
        >
          No OWASP-aligned vulnerability patterns detected for the selected
          language and categories.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div
        className="flex items-center justify-between px-4 py-3 rounded-lg"
        style={{
          background: "oklch(0.48 0.20 145 / 0.06)",
          border: "1px solid oklch(0.48 0.20 145 / 0.25)",
        }}
      >
        <div className="flex items-center gap-2">
          <ShieldCheck
            className="w-5 h-5"
            style={{ color: "oklch(0.38 0.18 145)" }}
          />
          <div>
            <p
              className="text-sm font-bold"
              style={{ color: "oklch(0.25 0.02 250)" }}
            >
              Secure Version Ready
            </p>
            <p
              className="text-xs font-mono"
              style={{ color: "oklch(0.50 0.03 250)" }}
            >
              {findings.length} issue{findings.length !== 1 ? "s" : ""} detected
              and remediated — load into editor and re-analyze to confirm zero
              findings
            </p>
          </div>
        </div>
      </div>
      <FixedCodePanel
        fixedCode={fixedCode}
        findingsCount={findings.length}
        onLoadIntoEditor={onLoadIntoEditor}
        mode="scanner"
      />
    </div>
  );
}

// ─── Developer Mode Results ───────────────────────────────────────────────────
interface DeveloperResultsProps {
  findings: Finding[];
}

function DeveloperResults({ findings }: DeveloperResultsProps) {
  if (findings.length === 0) {
    return (
      <div
        data-ocid="workspace.empty_state"
        className="flex flex-col items-center py-12 text-center rounded-lg border"
        style={{
          background: "oklch(0.48 0.20 240 / 0.04)",
          border: "1px solid oklch(0.48 0.20 240 / 0.2)",
        }}
      >
        <div
          className="w-14 h-14 rounded-full flex items-center justify-center mb-4"
          style={{
            background: "oklch(0.48 0.20 240 / 0.08)",
            border: "1px solid oklch(0.48 0.20 240 / 0.25)",
          }}
        >
          <ShieldCheck
            className="w-7 h-7"
            style={{ color: "oklch(0.38 0.18 145)" }}
          />
        </div>
        <p
          className="text-base font-semibold mb-2"
          style={{ color: "oklch(0.15 0.02 250)" }}
        >
          No vulnerabilities detected in your code
        </p>
        <p
          className="text-sm max-w-sm font-mono"
          style={{ color: "oklch(0.55 0.03 250)" }}
        >
          No vulnerable patterns found for the selected language and OWASP
          categories. Your code appears secure.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div
        className="flex items-center justify-between px-3 py-2 rounded-lg"
        style={{
          background: "oklch(0.48 0.20 240 / 0.06)",
          border: "1px solid oklch(0.48 0.20 240 / 0.2)",
        }}
      >
        <span
          className="text-xs font-semibold font-mono"
          style={{ color: "oklch(0.40 0.20 240)" }}
        >
          🔧 DEVELOPER WORKSPACE
        </span>
        <span
          className="text-xs font-mono"
          style={{ color: "oklch(0.55 0.03 250)" }}
        >
          {findings.length} finding{findings.length !== 1 ? "s" : ""} · click to
          expand
        </span>
      </div>
      <div className="space-y-3">
        {findings.map((finding, i) => (
          <FindingCard
            key={`${finding.ruleId}-${finding.lineNumber}-${i}`}
            finding={finding}
            mode="developer"
            index={i}
          />
        ))}
      </div>
    </div>
  );
}

// ─── Bug Bounty Mode Results ──────────────────────────────────────────────────
interface BugBountyResultsProps {
  findings: Finding[];
}

function BugBountyResults({ findings }: BugBountyResultsProps) {
  if (findings.length === 0) {
    return (
      <div
        data-ocid="workspace.empty_state"
        className="flex flex-col items-center py-12 text-center rounded-lg border"
        style={{
          background: "oklch(0.45 0.22 25 / 0.03)",
          border: "1px solid oklch(0.45 0.22 25 / 0.2)",
        }}
      >
        <div
          className="w-14 h-14 rounded-full flex items-center justify-center mb-4"
          style={{
            background: "oklch(0.45 0.22 25 / 0.08)",
            border: "1px solid oklch(0.45 0.22 25 / 0.25)",
          }}
        >
          <ShieldCheck
            className="w-7 h-7"
            style={{ color: "oklch(0.38 0.18 145)" }}
          />
        </div>
        <p
          className="text-base font-semibold mb-2"
          style={{ color: "oklch(0.15 0.02 250)" }}
        >
          No attack vectors identified in this code
        </p>
        <p
          className="text-sm max-w-sm font-mono"
          style={{ color: "oklch(0.55 0.03 250)" }}
        >
          No exploitable patterns detected for the selected language and OWASP
          categories. No attack surface identified.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div
        className="flex items-center justify-between px-3 py-2 rounded-lg"
        style={{
          background: "oklch(0.45 0.22 25 / 0.05)",
          border: "1px solid oklch(0.45 0.22 25 / 0.2)",
        }}
      >
        <span
          className="text-xs font-semibold font-mono"
          style={{ color: "oklch(0.40 0.20 25)" }}
        >
          🎯 THREAT INTEL WORKSPACE — Attacker Mindset
        </span>
        <span
          className="text-xs font-mono"
          style={{ color: "oklch(0.55 0.03 250)" }}
        >
          {findings.length} attack vector{findings.length !== 1 ? "s" : ""} · no
          fixes shown
        </span>
      </div>
      <div className="space-y-3">
        {findings.map((finding, i) => (
          <FindingCard
            key={`${finding.ruleId}-${finding.lineNumber}-${i}`}
            finding={finding}
            mode="bugbounty"
            index={i}
          />
        ))}
      </div>
      <div
        className="flex items-start gap-2 px-4 py-3 rounded-lg text-xs font-mono"
        style={{
          background: "oklch(0.45 0.22 25 / 0.04)",
          border: "1px solid oklch(0.45 0.22 25 / 0.15)",
          color: "oklch(0.45 0.03 250)",
        }}
      >
        <AlertCircle
          className="w-3.5 h-3.5 mt-0.5 shrink-0"
          style={{ color: "oklch(0.55 0.22 25)" }}
        />
        <span>
          Analysis is strictly client-side and static. No network requests,
          exploitation, or live system scanning. Manual verification checklists
          are for responsible, authorized testing only.
        </span>
      </div>
    </div>
  );
}
