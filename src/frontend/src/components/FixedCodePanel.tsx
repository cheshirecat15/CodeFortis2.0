import { Button } from "@/components/ui/button";
import { ArrowDownToLine, Check, Copy, ShieldCheck } from "lucide-react";
import { useState } from "react";

interface FixedCodePanelProps {
  fixedCode: string;
  findingsCount: number;
  onLoadIntoEditor: (code: string) => void;
  mode?: "developer" | "bugbounty" | "scanner";
}

export function FixedCodePanel({
  fixedCode,
  findingsCount,
  onLoadIntoEditor,
  mode = "scanner",
}: FixedCodePanelProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(fixedCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // fallback
    }
  };

  const accentColor =
    mode === "bugbounty" ? "oklch(0.55 0.22 25)" : "oklch(0.48 0.20 145)";

  const accentBg =
    mode === "bugbounty"
      ? "oklch(0.55 0.22 25 / 0.06)"
      : "oklch(0.48 0.20 145 / 0.06)";

  const accentBorder =
    mode === "bugbounty"
      ? "oklch(0.55 0.22 25 / 0.2)"
      : "oklch(0.48 0.20 145 / 0.2)";

  return (
    <div
      data-ocid="fixed-code.panel"
      className="rounded-lg border overflow-hidden"
      style={{
        background: "oklch(var(--card))",
        borderColor: accentBorder,
        boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
      }}
    >
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-3 border-b"
        style={{
          background: accentBg,
          borderColor: accentBorder,
        }}
      >
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4" style={{ color: accentColor }} />
          <span
            className="text-sm font-semibold"
            style={{ color: accentColor }}
          >
            {mode === "bugbounty" ? "Code Reference" : "Secure Version"}
          </span>
          <span
            className="text-xs font-mono px-1.5 py-0.5 rounded"
            style={{
              background: accentBg,
              color: accentColor,
              border: `1px solid ${accentBorder}`,
            }}
          >
            {findingsCount} fix{findingsCount !== 1 ? "es" : ""} applied
          </span>
        </div>
        <div className="flex items-center gap-2">
          <Button
            data-ocid="fixed-code.secondary_button"
            size="sm"
            variant="ghost"
            className="h-7 text-xs gap-1.5"
            style={{ color: "oklch(var(--muted-foreground))" }}
            onClick={handleCopy}
          >
            {copied ? (
              <>
                <Check
                  className="w-3.5 h-3.5"
                  style={{ color: "oklch(var(--success-accent))" }}
                />
                Copied!
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5" />
                Copy
              </>
            )}
          </Button>
          {mode !== "bugbounty" && (
            <Button
              data-ocid="fixed-code.primary_button"
              size="sm"
              className="h-7 text-xs gap-1.5"
              style={{
                background: accentColor,
                color: "white",
                border: "none",
              }}
              onClick={() => onLoadIntoEditor(fixedCode)}
            >
              <ArrowDownToLine className="w-3.5 h-3.5" />
              Load into Editor
            </Button>
          )}
        </div>
      </div>

      {/* Code block */}
      <div className="relative overflow-auto max-h-96">
        <pre
          className="p-4 text-xs font-mono leading-relaxed"
          style={{
            background: "oklch(var(--code-bg))",
            color: "oklch(0.20 0.02 250)",
            margin: 0,
          }}
        >
          <code>{fixedCode}</code>
        </pre>
      </div>
    </div>
  );
}
