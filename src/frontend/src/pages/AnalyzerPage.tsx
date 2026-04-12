import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ChevronDown,
  Code2,
  Loader2,
  Play,
  Radio,
  RotateCcw,
  ScanSearch,
  Square as StopIcon,
  Target,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { AppHeader } from "../components/AppHeader";
import { LoadingAnimation } from "../components/LoadingAnimation";
import { WorkspacePanel } from "../components/WorkspacePanel";
import { analyzeCode } from "../engine/patternMatcher";
import type { Finding } from "../types/findings";
import type { OWASPCategory, SupportedLanguage } from "../types/rules";
import { applyFixes } from "../utils/codeFixApplicator";
import {
  detectCodeLanguage,
  getLanguageLabel,
} from "../utils/languageDetector";
import { checkSyntax } from "../utils/syntaxChecker";

const LANGUAGES: { value: SupportedLanguage; label: string }[] = [
  { value: "javascript", label: "JavaScript" },
  { value: "typescript", label: "TypeScript" },
  { value: "python", label: "Python" },
  { value: "java", label: "Java" },
  { value: "php", label: "PHP" },
  { value: "go", label: "Go" },
  { value: "csharp", label: "C#" },
];

const OWASP_CATEGORIES: OWASPCategory[] = [
  "A01:2021 – Broken Access Control",
  "A02:2021 – Cryptographic Failures",
  "A03:2021 – Injection",
  "A04:2021 – Insecure Design",
  "A05:2021 – Security Misconfiguration",
  "A06:2021 – Vulnerable and Outdated Components",
  "A07:2021 – Identification and Authentication Failures",
  "A08:2021 – Software and Data Integrity Failures",
  "A09:2021 – Security Logging and Monitoring Failures",
  "A10:2021 – Server-Side Request Forgery (SSRF)",
];

type AnalysisState = "idle" | "analyzing" | "done";

export function AnalyzerPage() {
  // ── Shared input state ──────────────────────────────────────────────────────
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState<SupportedLanguage>("javascript");
  const [selectedCategories, setSelectedCategories] = useState<OWASPCategory[]>(
    [...OWASP_CATEGORIES],
  );

  // ── Shared analysis state (lifted — all three panels share these) ───────────
  const [findings, setFindings] = useState<Finding[]>([]);
  const [fixedCode, setFixedCode] = useState("");
  const [analysisState, setAnalysisState] = useState<AnalysisState>("idle");
  const [hasAnalyzed, setHasAnalyzed] = useState(false);
  const [liveMode, setLiveMode] = useState(false);
  const [langMismatch, setLangMismatch] = useState<string | null>(null);
  const [syntaxErrors, setSyntaxErrors] = useState<
    ReturnType<typeof checkSyntax>["errors"]
  >([]);

  const liveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isAnalyzing = analysisState === "analyzing";

  // ── Core analysis function — runs ONCE, results shared to all panels ────────
  const runAnalysis = useCallback(
    (codeVal: string, langVal: SupportedLanguage, catsVal: OWASPCategory[]) => {
      if (!codeVal.trim()) return;

      const detected = detectCodeLanguage(codeVal);
      if (detected && detected !== langVal) {
        setLangMismatch(
          `Code appears to be ${getLanguageLabel(detected)} but ${getLanguageLabel(langVal)} is selected. Results may be incomplete.`,
        );
      } else {
        setLangMismatch(null);
      }

      const syntaxResult = checkSyntax(codeVal);
      setSyntaxErrors(syntaxResult.errors);

      setAnalysisState("analyzing");
      setHasAnalyzed(false);

      setTimeout(
        () => {
          const results = analyzeCode(codeVal, langVal, catsVal);
          setFindings(results);
          setFixedCode(applyFixes(codeVal, results));
          setAnalysisState("done");
          setHasAnalyzed(true);
        },
        liveMode ? 200 : 1000,
      );
    },
    [liveMode],
  );

  // ── Live analysis: debounced re-run on any input change ─────────────────────
  useEffect(() => {
    if (!liveMode || !code.trim()) return;

    if (liveTimerRef.current) clearTimeout(liveTimerRef.current);
    liveTimerRef.current = setTimeout(() => {
      runAnalysis(code, language, selectedCategories);
    }, 800);

    return () => {
      if (liveTimerRef.current) clearTimeout(liveTimerRef.current);
    };
  }, [code, language, selectedCategories, liveMode, runAnalysis]);

  // ── Load-example event from WorkspacePanel ──────────────────────────────────
  useEffect(() => {
    const handler = (e: Event) => {
      const detail = (e as CustomEvent<{ code: string }>).detail;
      if (detail?.code !== undefined) {
        setCode(detail.code);
        setFindings([]);
        setFixedCode("");
        setHasAnalyzed(false);
        setAnalysisState("idle");
      }
    };
    window.addEventListener("codefortis:load-example", handler);
    return () => window.removeEventListener("codefortis:load-example", handler);
  }, []);

  const handleAnalyze = useCallback(() => {
    runAnalysis(code, language, selectedCategories);
  }, [code, language, selectedCategories, runAnalysis]);

  const handleReset = useCallback(() => {
    setFindings([]);
    setFixedCode("");
    setAnalysisState("idle");
    setHasAnalyzed(false);
    setLangMismatch(null);
    setSyntaxErrors([]);
    if (liveTimerRef.current) clearTimeout(liveTimerRef.current);
  }, []);

  const toggleCategory = (cat: OWASPCategory) => {
    setSelectedCategories((prev) =>
      prev.includes(cat) ? prev.filter((c) => c !== cat) : [...prev, cat],
    );
  };

  const categoryLabel =
    selectedCategories.length === 0
      ? "None selected"
      : selectedCategories.length === OWASP_CATEGORIES.length
        ? "All categories"
        : `${selectedCategories.length} selected`;

  return (
    <div
      className="min-h-screen flex flex-col"
      style={{ background: "oklch(var(--background))" }}
    >
      <AppHeader />

      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-6">
        {/* Hero */}
        <div className="mb-6">
          <p
            className="text-xs font-mono uppercase tracking-wider mb-1"
            style={{ color: "oklch(0.55 0.03 250)", letterSpacing: "0.10em" }}
          >
            OWASP Top 10 · Client-side · No data transmitted
          </p>
          <h2
            className="text-2xl font-bold tracking-tight font-display"
            style={{ color: "oklch(0.15 0.02 250)" }}
          >
            Static Code Analysis
          </h2>
          <p
            className="text-sm mt-1 max-w-2xl"
            style={{ color: "oklch(0.45 0.03 250)" }}
          >
            Paste your code once — analysis runs automatically across all three
            workspaces. Switch modes below to change perspective.
          </p>
        </div>

        {/* ── Shared Code Input + Controls ────────────────────────────────── */}
        <div
          className="mb-4 p-4 rounded-xl space-y-4"
          style={{
            background: "oklch(var(--card))",
            border: "1px solid oklch(var(--border))",
            boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
          }}
        >
          <p
            className="text-xs font-mono uppercase tracking-wider"
            style={{ color: "oklch(0.55 0.03 250)", letterSpacing: "0.08em" }}
          >
            Shared Input — applies to all workspaces
          </p>

          {/* Language + Category row */}
          <div className="flex flex-wrap gap-4 items-end">
            <div className="flex flex-col gap-1.5 min-w-[150px]">
              <Label
                className="text-xs font-mono uppercase tracking-wider"
                style={{
                  color: "oklch(0.50 0.03 250)",
                  letterSpacing: "0.08em",
                }}
              >
                Language
              </Label>
              <Select
                value={language}
                onValueChange={(v) => setLanguage(v as SupportedLanguage)}
              >
                <SelectTrigger
                  data-ocid="shared.select"
                  className="h-9 text-sm font-mono"
                  style={{
                    background: "oklch(0.97 0.005 240)",
                    border: "1px solid oklch(var(--border))",
                    color: "oklch(0.15 0.02 250)",
                  }}
                >
                  <SelectValue />
                </SelectTrigger>
                <SelectContent
                  style={{
                    background: "oklch(var(--popover))",
                    border: "1px solid oklch(var(--border))",
                  }}
                >
                  {LANGUAGES.map((lang) => (
                    <SelectItem
                      key={lang.value}
                      value={lang.value}
                      className="font-mono text-sm"
                    >
                      {lang.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="flex flex-col gap-1.5 min-w-[190px]">
              <Label
                className="text-xs font-mono uppercase tracking-wider"
                style={{
                  color: "oklch(0.50 0.03 250)",
                  letterSpacing: "0.08em",
                }}
              >
                OWASP Categories
              </Label>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button
                    data-ocid="shared.toggle"
                    variant="outline"
                    className="h-9 text-sm justify-between font-mono min-w-[190px]"
                    style={{
                      background: "oklch(0.97 0.005 240)",
                      border: "1px solid oklch(var(--border))",
                      color:
                        selectedCategories.length === 0
                          ? "oklch(0.55 0.22 25)"
                          : "oklch(0.15 0.02 250)",
                    }}
                  >
                    <span className="truncate">{categoryLabel}</span>
                    <ChevronDown className="w-4 h-4 ml-2 shrink-0 opacity-50" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent
                  className="w-80"
                  style={{
                    background: "oklch(var(--popover))",
                    border: "1px solid oklch(var(--border))",
                  }}
                  align="start"
                >
                  <DropdownMenuLabel
                    className="text-xs font-mono"
                    style={{ color: "oklch(0.50 0.03 250)" }}
                  >
                    Filter by OWASP Top 10
                  </DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <div className="flex gap-2 px-2 py-1">
                    <button
                      type="button"
                      onClick={() =>
                        setSelectedCategories([...OWASP_CATEGORIES])
                      }
                      className="text-xs font-mono px-2 py-0.5 rounded transition-colors hover:bg-muted"
                      style={{ color: "oklch(0.48 0.20 240)" }}
                    >
                      All
                    </button>
                    <button
                      type="button"
                      onClick={() => setSelectedCategories([])}
                      className="text-xs font-mono px-2 py-0.5 rounded transition-colors hover:bg-muted"
                      style={{ color: "oklch(0.55 0.03 250)" }}
                    >
                      None
                    </button>
                  </div>
                  <DropdownMenuSeparator />
                  {OWASP_CATEGORIES.map((cat) => (
                    <DropdownMenuCheckboxItem
                      key={cat}
                      checked={selectedCategories.includes(cat)}
                      onCheckedChange={() => toggleCategory(cat)}
                      className="text-xs font-mono"
                    >
                      {cat}
                    </DropdownMenuCheckboxItem>
                  ))}
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>

          {/* Code textarea */}
          <div>
            <Label
              className="text-xs font-mono uppercase tracking-wider mb-1.5 block"
              style={{ color: "oklch(0.50 0.03 250)", letterSpacing: "0.08em" }}
            >
              Code Input
            </Label>
            <textarea
              data-ocid="shared.editor"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder={`// Paste ${LANGUAGES.find((l) => l.value === language)?.label ?? "code"} here…\n// Switch between Scanner, Developer, and Bug Bounty modes below — same code, different perspective.`}
              rows={14}
              className="w-full resize-y text-sm font-mono rounded-lg p-4 outline-none transition-all duration-200 placeholder:opacity-40"
              style={{
                background: "oklch(0.97 0.005 240)",
                border: "1px solid oklch(var(--border))",
                color: "oklch(0.15 0.02 250)",
                caretColor: "oklch(0.48 0.20 240)",
                boxShadow: "0 1px 3px rgba(0,0,0,0.06)",
              }}
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
            />
            <div className="flex justify-between items-center mt-1.5">
              <span
                className="text-xs font-mono"
                style={{ color: "oklch(0.62 0.02 250)" }}
              >
                {code.length > 0
                  ? `${code.split("\n").length} lines · ${code.length} chars`
                  : "No input"}
              </span>
              {selectedCategories.length > 0 &&
                selectedCategories.length < OWASP_CATEGORIES.length && (
                  <span
                    className="text-xs font-mono"
                    style={{ color: "oklch(0.55 0.03 250)" }}
                  >
                    {selectedCategories.length}/{OWASP_CATEGORIES.length}{" "}
                    categories
                  </span>
                )}
            </div>
          </div>

          {/* ── Shared Action Controls ─────────────────────────────────────── */}
          <div
            className="flex flex-wrap gap-3 items-center pt-1 border-t"
            style={{ borderColor: "oklch(var(--border))" }}
          >
            {/* Live mode toggle */}
            <div className="flex flex-col gap-1">
              <Label
                className="text-xs font-mono uppercase tracking-wider"
                style={{
                  color: "oklch(0.50 0.03 250)",
                  letterSpacing: "0.08em",
                }}
              >
                Live Analysis
              </Label>
              <div className="flex items-center gap-2 h-9">
                <Switch
                  data-ocid="workspace.switch"
                  checked={liveMode}
                  onCheckedChange={setLiveMode}
                />
                {liveMode && (
                  <span
                    className="text-xs font-mono font-bold px-2 py-0.5 rounded-full flex items-center gap-1"
                    style={{
                      background: "oklch(0.48 0.20 145 / 0.12)",
                      color: "oklch(0.38 0.18 145)",
                      border: "1px solid oklch(0.48 0.20 145 / 0.3)",
                      animation: "live-pulse 1.5s ease-in-out infinite",
                    }}
                  >
                    <span
                      className="w-1.5 h-1.5 rounded-full inline-block"
                      style={{ background: "oklch(0.48 0.20 145)" }}
                    />
                    LIVE
                  </span>
                )}
              </div>
            </div>

            {/* Action buttons */}
            <div className="flex gap-2 ml-auto items-end">
              <Button
                variant="ghost"
                size="sm"
                onClick={handleReset}
                disabled={isAnalyzing}
                className="h-9 text-xs font-mono gap-1.5"
                style={{ color: "oklch(0.50 0.03 250)" }}
                data-ocid="workspace.secondary_button"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                Reset
              </Button>

              {!liveMode && (
                <Button
                  data-ocid="workspace.primary_button"
                  size="sm"
                  onClick={handleAnalyze}
                  disabled={
                    isAnalyzing ||
                    !code.trim() ||
                    selectedCategories.length === 0
                  }
                  className="h-9 text-sm font-semibold gap-1.5 transition-all duration-200"
                  style={{
                    background: isAnalyzing
                      ? "oklch(0.90 0.008 240)"
                      : "oklch(0.48 0.20 240)",
                    color: isAnalyzing ? "oklch(0.55 0.03 250)" : "white",
                    border: "none",
                    minWidth: "160px",
                  }}
                >
                  {isAnalyzing ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      Scanning all modes…
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5" />
                      Run Analysis
                    </>
                  )}
                </Button>
              )}

              {liveMode && isAnalyzing && (
                <span
                  className="h-9 flex items-center gap-2 px-3 text-sm font-medium rounded-md"
                  data-ocid="workspace.loading_state"
                  style={{
                    background: "oklch(0.48 0.20 145 / 0.08)",
                    color: "oklch(0.38 0.18 145)",
                    border: "1px solid oklch(0.48 0.20 145 / 0.2)",
                  }}
                >
                  <Radio className="w-3.5 h-3.5 animate-spin" />
                  Analyzing…
                </span>
              )}

              {liveMode && !isAnalyzing && (
                <Button
                  data-ocid="workspace.toggle"
                  size="sm"
                  variant="outline"
                  onClick={() => setLiveMode(false)}
                  className="h-9 text-xs font-mono gap-1.5"
                  style={{
                    color: "oklch(0.45 0.22 25)",
                    borderColor: "oklch(0.45 0.22 25 / 0.3)",
                  }}
                >
                  <StopIcon className="w-3.5 h-3.5" />
                  Stop Live
                </Button>
              )}
            </div>
          </div>
        </div>

        {/* Loading animation (manual mode only) */}
        {isAnalyzing && !liveMode && (
          <div className="mb-4">
            <LoadingAnimation />
          </div>
        )}

        {/* ── Three-tab workspace ─────────────────────────────────────────── */}
        <Tabs
          defaultValue="scanner"
          className="w-full"
          data-ocid="workspace.tab"
        >
          <TabsList
            className="mb-6 h-11 gap-1 p-1"
            style={{
              background: "oklch(0.93 0.008 240)",
              border: "1px solid oklch(var(--border))",
            }}
          >
            <TabsTrigger
              data-ocid="workspace.tab"
              value="scanner"
              className="flex items-center gap-2 text-sm font-medium data-[state=active]:shadow-sm transition-all"
              style={{ borderRadius: "calc(var(--radius) - 2px)" }}
            >
              <ScanSearch className="w-4 h-4" />
              Scanner
            </TabsTrigger>
            <TabsTrigger
              data-ocid="workspace.tab"
              value="developer"
              className="flex items-center gap-2 text-sm font-medium data-[state=active]:shadow-sm transition-all"
              style={{ borderRadius: "calc(var(--radius) - 2px)" }}
            >
              <Code2 className="w-4 h-4" />
              Developer Mode
            </TabsTrigger>
            <TabsTrigger
              data-ocid="workspace.tab"
              value="bugbounty"
              className="flex items-center gap-2 text-sm font-medium data-[state=active]:shadow-sm transition-all"
              style={{ borderRadius: "calc(var(--radius) - 2px)" }}
            >
              <Target className="w-4 h-4" />
              Bug Bounty Mode
            </TabsTrigger>
          </TabsList>

          <TabsContent value="scanner" className="mt-0">
            <div
              className="p-5 rounded-xl"
              style={{
                background: "oklch(var(--card))",
                border: "1px solid oklch(var(--border))",
                boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
              }}
            >
              <WorkspacePanel
                mode="scanner"
                code={code}
                language={language}
                selectedCategories={selectedCategories}
                findings={findings}
                fixedCode={fixedCode}
                analysisState={analysisState}
                hasAnalyzed={hasAnalyzed}
                langMismatch={langMismatch}
                syntaxErrors={syntaxErrors}
                onSyntaxErrorsDismiss={() => setSyntaxErrors([])}
              />
            </div>
          </TabsContent>

          <TabsContent value="developer" className="mt-0">
            <div
              className="p-5 rounded-xl"
              style={{
                background: "oklch(var(--card))",
                border: "1px solid oklch(0.48 0.20 240 / 0.2)",
                boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
              }}
            >
              <WorkspacePanel
                mode="developer"
                code={code}
                language={language}
                selectedCategories={selectedCategories}
                findings={findings}
                fixedCode={fixedCode}
                analysisState={analysisState}
                hasAnalyzed={hasAnalyzed}
                langMismatch={langMismatch}
                syntaxErrors={syntaxErrors}
                onSyntaxErrorsDismiss={() => setSyntaxErrors([])}
              />
            </div>
          </TabsContent>

          <TabsContent value="bugbounty" className="mt-0">
            <div
              className="p-5 rounded-xl"
              style={{
                background: "oklch(var(--card))",
                border: "1px solid oklch(0.55 0.22 25 / 0.2)",
                boxShadow: "0 1px 4px rgba(0,0,0,0.06)",
              }}
            >
              <WorkspacePanel
                mode="bugbounty"
                code={code}
                language={language}
                selectedCategories={selectedCategories}
                findings={findings}
                fixedCode={fixedCode}
                analysisState={analysisState}
                hasAnalyzed={hasAnalyzed}
                langMismatch={langMismatch}
                syntaxErrors={syntaxErrors}
                onSyntaxErrorsDismiss={() => setSyntaxErrors([])}
              />
            </div>
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer
        className="mt-auto"
        style={{
          borderTop: "1px solid oklch(var(--border))",
          background: "oklch(0.99 0.003 240)",
        }}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <p
            className="text-xs font-mono"
            style={{ color: "oklch(0.60 0.02 250)", letterSpacing: "0.04em" }}
          >
            © {new Date().getFullYear()} CodeFortis · OWASP Static Analysis · No
            data transmitted
          </p>
        </div>
      </footer>
    </div>
  );
}
