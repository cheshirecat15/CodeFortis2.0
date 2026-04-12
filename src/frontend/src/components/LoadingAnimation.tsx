import { Loader2 } from "lucide-react";
import { useEffect, useState } from "react";

const SCAN_MESSAGES = [
  "Initializing analysis pipeline…",
  "Parsing code structure…",
  "Cross-referencing OWASP rule library…",
  "Analyzing code patterns…",
  "Detecting vulnerability signatures…",
  "Running deep pattern recognition…",
  "Compiling findings…",
  "Finalizing analysis…",
];

export function LoadingAnimation() {
  const [messageIndex, setMessageIndex] = useState(0);
  const [progress, setProgress] = useState(0);
  const [dots, setDots] = useState("");

  useEffect(() => {
    const msgInterval = setInterval(() => {
      setMessageIndex((prev) => (prev + 1) % SCAN_MESSAGES.length);
    }, 800);

    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 92) return prev;
        return prev + Math.random() * 5;
      });
    }, 180);

    const dotsInterval = setInterval(() => {
      setDots((prev) => (prev.length >= 3 ? "" : `${prev}.`));
    }, 400);

    return () => {
      clearInterval(msgInterval);
      clearInterval(progressInterval);
      clearInterval(dotsInterval);
    };
  }, []);

  return (
    <div
      className="flex flex-col items-center justify-center py-12 px-4 select-none rounded-lg"
      style={{
        background: "oklch(var(--card))",
        border: "1px solid oklch(var(--border))",
      }}
    >
      {/* Spinner */}
      <div className="relative flex items-center justify-center mb-6">
        <div
          className="absolute w-20 h-20 rounded-full border-2"
          style={{
            borderColor: "oklch(0.48 0.20 240 / 0.15)",
            borderTopColor: "oklch(0.48 0.20 240)",
            animation: "spin-slow 1.2s linear infinite",
          }}
        />
        <div
          className="absolute w-14 h-14 rounded-full border"
          style={{
            borderColor: "oklch(0.55 0.22 25 / 0.12)",
            borderBottomColor: "oklch(0.55 0.22 25 / 0.7)",
            animation: "spin-slow 1.8s linear infinite reverse",
          }}
        />
        <div
          className="w-9 h-9 rounded-full flex items-center justify-center"
          style={{
            background: "oklch(0.48 0.20 240 / 0.08)",
            border: "1px solid oklch(0.48 0.20 240 / 0.3)",
          }}
        >
          <Loader2
            className="w-5 h-5 animate-spin"
            style={{ color: "oklch(0.48 0.20 240)" }}
          />
        </div>
      </div>

      {/* Scan message */}
      <p
        className="text-sm font-medium mb-4 text-center"
        style={{ color: "oklch(0.25 0.02 250)", minHeight: "1.4rem" }}
      >
        {SCAN_MESSAGES[messageIndex]}
        {dots}
      </p>

      {/* Progress bar */}
      <div
        className="w-full max-w-xs rounded-full overflow-hidden mb-2"
        style={{
          height: 4,
          background: "oklch(0.90 0.008 240)",
          border: "1px solid oklch(0.85 0.01 240)",
        }}
      >
        <div
          className="h-full rounded-full transition-all duration-300"
          style={{
            width: `${Math.min(progress, 92)}%`,
            background:
              "linear-gradient(90deg, oklch(0.48 0.20 240), oklch(0.55 0.16 200))",
          }}
        />
      </div>

      <p
        className="text-xs font-mono"
        style={{ color: "oklch(0.55 0.03 250)" }}
      >
        {Math.min(Math.round(progress), 92)}%
      </p>
    </div>
  );
}
