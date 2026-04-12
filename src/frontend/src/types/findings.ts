import type { OWASPCategory, Severity } from "./rules";

export type AnalysisMode = "developer" | "bugbounty";

export interface Finding {
  lineNumber: number;
  matchedText: string;
  ruleId: string;
  ruleName: string;
  owaspCategory: OWASPCategory;
  severity: Severity;
  developerExplanation: string;
  secureAlternative: string;
  suggestedFix?: string;
  threatScenario: string;
  attackerPerspective: string;
  exploitationReasoning: string;
  impactAnalysis: string;
  bypassConsiderations: string;
  manualVerificationChecklist: string[];
}
