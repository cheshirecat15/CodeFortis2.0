import { AlertTriangle, ChevronDown, ChevronUp, X } from "lucide-react";
import { useState } from "react";
import type { SyntaxIssue } from "../utils/syntaxChecker";

interface SyntaxErrorBannerProps {
  errors: SyntaxIssue[];
  onDismiss?: () => void;
}

export function SyntaxErrorBanner({
  errors,
  onDismiss,
}: SyntaxErrorBannerProps) {
  const [expanded, setExpanded] = useState(true);

  if (errors.length === 0) return null;

  return (
    <div
      data-ocid="syntax.error_state"
      className="rounded-lg border overflow-hidden mb-4"
      style={{
        background: "oklch(0.98 0.01 65)",
        borderColor: "oklch(0.65 0.18 65 / 0.5)",
        boxShadow: "0 1px 4px oklch(0.65 0.18 65 / 0.12)",
      }}
    >
      {/* Header row */}
      <div
        className="flex items-center gap-2 px-4 py-2.5"
        style={{ background: "oklch(0.96 0.015 65 / 0.6)" }}
      >
        <AlertTriangle
          className="w-4 h-4 shrink-0"
          style={{ color: "oklch(0.55 0.18 65)" }}
        />
        <span
          className="text-sm font-semibold flex-1"
          style={{ color: "oklch(0.35 0.10 65)" }}
        >
          {errors.length} Syntax {errors.length === 1 ? "Issue" : "Issues"}{" "}
          Detected
        </span>
        <button
          type="button"
          className="text-xs font-mono px-2 py-0.5 rounded hover:bg-black/5 transition-colors"
          style={{ color: "oklch(0.50 0.08 65)" }}
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? "Hide" : "Show"}
          {expanded ? (
            <ChevronUp
              className="inline w-3.5 h-3.5 ml-1"
              style={{ color: "oklch(0.55 0.18 65)" }}
            />
          ) : (
            <ChevronDown
              className="inline w-3.5 h-3.5 ml-1"
              style={{ color: "oklch(0.55 0.18 65)" }}
            />
          )}
        </button>
        {onDismiss && (
          <button
            type="button"
            onClick={onDismiss}
            className="ml-1 p-0.5 rounded hover:bg-black/10 transition-colors"
            aria-label="Dismiss"
          >
            <X
              className="w-3.5 h-3.5"
              style={{ color: "oklch(0.50 0.08 65)" }}
            />
          </button>
        )}
      </div>

      {/* Error list */}
      {expanded && (
        <div className="px-4 py-3 space-y-1.5">
          {errors.map((err) => (
            <div
              key={`${err.line}-${err.message}`}
              className="flex items-start gap-2 text-sm font-mono"
            >
              <span
                className="shrink-0 px-1.5 py-0.5 rounded text-xs font-bold"
                style={{
                  background: "oklch(0.65 0.18 65 / 0.15)",
                  color: "oklch(0.45 0.18 65)",
                }}
              >
                L{err.line}
              </span>
              <span style={{ color: "oklch(0.30 0.08 65)" }}>
                {err.message}
              </span>
            </div>
          ))}
          <p
            className="text-xs mt-2 pt-2 border-t"
            style={{
              borderColor: "oklch(0.65 0.18 65 / 0.2)",
              color: "oklch(0.50 0.08 65)",
            }}
          >
            The "Fixed Code" panel attempts to auto-correct these issues.
          </p>
        </div>
      )}
    </div>
  );
}
