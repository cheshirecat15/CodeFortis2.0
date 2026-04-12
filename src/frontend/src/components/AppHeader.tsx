import { Shield } from "lucide-react";

export function AppHeader() {
  return (
    <header
      className="sticky top-0 z-50"
      style={{
        background: "oklch(0.99 0.003 240 / 0.96)",
        borderBottom: "1px solid oklch(0.88 0.01 240)",
        backdropFilter: "blur(12px)",
        boxShadow: "0 1px 8px rgba(0,0,0,0.06)",
      }}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-14">
          <div className="flex items-center gap-3">
            <div className="relative">
              <img
                src="/assets/generated/codefortis-alien-logo.dim_256x256.png"
                alt="CodeFortis Logo"
                className="w-8 h-8 rounded-md object-contain"
                style={{ filter: "none" }}
                onError={(e) => {
                  (e.target as HTMLImageElement).style.display = "none";
                  const fallback = (e.target as HTMLImageElement)
                    .nextElementSibling as HTMLElement;
                  if (fallback) fallback.style.display = "flex";
                }}
              />
              <div
                className="w-8 h-8 rounded-lg items-center justify-center shrink-0"
                style={{
                  display: "none",
                  background: "oklch(0.48 0.20 240 / 0.1)",
                  border: "1px solid oklch(0.48 0.20 240 / 0.3)",
                }}
              >
                <Shield
                  className="w-5 h-5"
                  style={{ color: "oklch(0.48 0.20 240)" }}
                  aria-hidden="true"
                />
              </div>
            </div>
            <div>
              <h1
                className="text-lg font-bold tracking-tight font-display leading-none"
                style={{ color: "oklch(0.15 0.02 250)" }}
              >
                Code
                <span style={{ color: "oklch(0.48 0.20 240)" }}>Fortis</span>
              </h1>
              <p
                className="text-xs leading-none font-mono mt-0.5"
                style={{
                  color: "oklch(0.55 0.03 250)",
                  letterSpacing: "0.05em",
                }}
              >
                OWASP Static Analysis
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span
              className="hidden sm:flex items-center gap-1.5 text-xs font-mono px-3 py-1.5 rounded-full"
              style={{
                color: "oklch(0.45 0.03 250)",
                background: "oklch(0.93 0.008 240)",
                border: "1px solid oklch(0.88 0.01 240)",
                letterSpacing: "0.04em",
              }}
            >
              <span
                className="w-1.5 h-1.5 rounded-full inline-block shrink-0"
                style={{
                  background: "oklch(0.48 0.20 145)",
                  animation: "live-pulse 2.5s ease-in-out infinite",
                }}
              />
              Client-side · No data sent
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}
