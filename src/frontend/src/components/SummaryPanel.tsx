import {
  AlertTriangle,
  Info,
  ShieldAlert,
  ShieldCheck,
  Target,
} from "lucide-react";
import type { Finding } from "../types/findings";
import type { OWASPCategory, SupportedLanguage } from "../types/rules";

interface SummaryPanelProps {
  findings: Finding[];
  language: SupportedLanguage;
  selectedCategories: OWASPCategory[];
}

export function SummaryPanel({
  findings,
  language: _language,
  selectedCategories: _selectedCategories,
}: SummaryPanelProps) {
  const high = findings.filter((f) => f.severity === "high").length;
  const medium = findings.filter((f) => f.severity === "medium").length;
  const low = findings.filter((f) => f.severity === "low").length;

  const categoryMap = new Map<string, number>();
  for (const f of findings) {
    categoryMap.set(
      f.owaspCategory,
      (categoryMap.get(f.owaspCategory) ?? 0) + 1,
    );
  }
  const topCategories = Array.from(categoryMap.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4);

  const riskScore =
    findings.length === 0 ? 0 : Math.min(100, high * 15 + medium * 7 + low * 3);
  const riskLabel =
    riskScore === 0
      ? "CLEAN"
      : riskScore < 20
        ? "LOW RISK"
        : riskScore < 50
          ? "MEDIUM RISK"
          : riskScore < 80
            ? "HIGH RISK"
            : "CRITICAL";

  const riskColor =
    riskScore === 0
      ? "oklch(0.38 0.18 145)"
      : riskScore < 20
        ? "oklch(0.38 0.18 145)"
        : riskScore < 50
          ? "oklch(0.50 0.18 65)"
          : "oklch(0.45 0.22 25)";

  const cardStyle = {
    background: "oklch(var(--card))",
    border: "1px solid oklch(var(--border))",
    borderRadius: "0.5rem",
    boxShadow: "0 1px 3px rgba(0,0,0,0.06)",
  };

  return (
    <div
      data-ocid="summary.section"
      className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5"
    >
      {/* Total findings */}
      <div className="col-span-2 sm:col-span-1 p-4" style={cardStyle}>
        <div className="flex items-start justify-between">
          <div>
            <p
              className="text-xs font-mono uppercase tracking-wider mb-1"
              style={{ color: "oklch(0.55 0.03 250)", letterSpacing: "0.08em" }}
            >
              Total Findings
            </p>
            <p
              className="text-3xl font-bold font-mono"
              style={{ color: "oklch(0.15 0.02 250)" }}
            >
              {findings.length}
            </p>
            <p
              className="text-xs font-semibold mt-1 font-mono tracking-wider"
              style={{ color: riskColor }}
            >
              {riskLabel}
            </p>
          </div>
          <Target
            className="w-5 h-5 mt-0.5"
            style={{ color: "oklch(0.70 0.02 250)" }}
          />
        </div>
      </div>

      {/* Severity breakdown */}
      <div className="col-span-2 sm:col-span-1 p-4" style={cardStyle}>
        <p
          className="text-xs font-mono uppercase tracking-wider mb-2"
          style={{ color: "oklch(0.55 0.03 250)", letterSpacing: "0.08em" }}
        >
          By Severity
        </p>
        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <ShieldAlert
                className="w-3.5 h-3.5"
                style={{ color: "oklch(0.45 0.22 25)" }}
              />
              <span
                className="text-xs font-mono"
                style={{ color: "oklch(0.50 0.03 250)" }}
              >
                High
              </span>
            </div>
            <span
              className="text-sm font-bold font-mono"
              style={{ color: "oklch(0.45 0.22 25)" }}
            >
              {high}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <AlertTriangle
                className="w-3.5 h-3.5"
                style={{ color: "oklch(0.50 0.18 65)" }}
              />
              <span
                className="text-xs font-mono"
                style={{ color: "oklch(0.50 0.03 250)" }}
              >
                Medium
              </span>
            </div>
            <span
              className="text-sm font-bold font-mono"
              style={{ color: "oklch(0.50 0.18 65)" }}
            >
              {medium}
            </span>
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <Info
                className="w-3.5 h-3.5"
                style={{ color: "oklch(0.40 0.18 240)" }}
              />
              <span
                className="text-xs font-mono"
                style={{ color: "oklch(0.50 0.03 250)" }}
              >
                Low
              </span>
            </div>
            <span
              className="text-sm font-bold font-mono"
              style={{ color: "oklch(0.40 0.18 240)" }}
            >
              {low}
            </span>
          </div>
        </div>
      </div>

      {/* Top OWASP categories */}
      <div className="col-span-2 p-4" style={cardStyle}>
        <p
          className="text-xs font-mono uppercase tracking-wider mb-2"
          style={{ color: "oklch(0.55 0.03 250)", letterSpacing: "0.08em" }}
        >
          Top Vulnerability Categories
        </p>
        {topCategories.length === 0 ? (
          <div className="flex items-center gap-2">
            <ShieldCheck
              className="w-4 h-4"
              style={{ color: "oklch(0.38 0.18 145)" }}
            />
            <span
              className="text-sm font-mono"
              style={{ color: "oklch(0.38 0.18 145)" }}
            >
              No vulnerabilities detected
            </span>
          </div>
        ) : (
          <div className="space-y-1.5">
            {topCategories.map(([cat, count]) => (
              <div
                key={cat}
                className="flex items-center justify-between gap-2"
              >
                <span
                  className="text-xs font-mono truncate flex-1"
                  style={{ color: "oklch(0.45 0.03 250)" }}
                >
                  {cat.split(" – ")[1] ?? cat}
                </span>
                <span
                  className="text-xs font-bold font-mono shrink-0"
                  style={{ color: "oklch(0.15 0.02 250)" }}
                >
                  {count}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
