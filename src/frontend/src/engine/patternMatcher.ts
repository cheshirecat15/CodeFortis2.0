import type { Finding } from "../types/findings";
import type { OWASPCategory, SupportedLanguage } from "../types/rules";
import { filterRules } from "../utils/ruleFilters";

export function analyzeCode(
  code: string,
  language: SupportedLanguage,
  selectedCategories: OWASPCategory[],
): Finding[] {
  const applicableRules = filterRules(language, selectedCategories);
  const rawFindings: Finding[] = [];
  const lines = code.split("\n");

  for (const rule of applicableRules) {
    const flags = rule.patternFlags ?? "i";
    let regex: RegExp;
    try {
      regex = new RegExp(rule.pattern, flags);
    } catch {
      continue;
    }

    // Strategy 1: Test each line individually (catches single-line patterns)
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (regex.test(line)) {
        rawFindings.push(buildFinding(rule, i + 1, line.trim()));
      }
    }

    // Strategy 2: Sliding window of up to 5 lines joined together.
    const WINDOW_SIZE = 5;
    for (let i = 0; i < lines.length; i++) {
      const windowEnd = Math.min(i + WINDOW_SIZE, lines.length);
      const windowText = lines.slice(i, windowEnd).join("\n");

      const alreadyMatchedOnLine = rawFindings.some(
        (f) => f.ruleId === rule.ruleId && f.lineNumber === i + 1,
      );
      if (!alreadyMatchedOnLine && regex.test(windowText)) {
        let matchLine = i;
        for (let j = i; j < windowEnd; j++) {
          if (regex.test(lines[j])) {
            matchLine = j;
            break;
          }
        }
        rawFindings.push(
          buildFinding(rule, matchLine + 1, lines[matchLine].trim()),
        );
      }
    }
  }

  // Deduplicate: keep only the FIRST occurrence per ruleId (one finding type = one finding)
  const seenRuleIds = new Set<string>();
  const deduplicated: Finding[] = [];
  for (const finding of rawFindings) {
    if (!seenRuleIds.has(finding.ruleId)) {
      seenRuleIds.add(finding.ruleId);
      deduplicated.push(finding);
    }
  }

  // Sort by severity (high → medium → low), then by line number
  const severityOrder: Record<string, number> = { high: 0, medium: 1, low: 2 };
  deduplicated.sort((a, b) => {
    const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
    if (severityDiff !== 0) return severityDiff;
    return a.lineNumber - b.lineNumber;
  });

  return deduplicated;
}

function buildFinding(
  rule: ReturnType<typeof filterRules>[number],
  lineNumber: number,
  matchedText: string,
): Finding {
  return {
    lineNumber,
    matchedText,
    ruleId: rule.ruleId,
    ruleName: rule.name,
    owaspCategory: rule.owaspCategory,
    severity: rule.severity,
    developerExplanation: rule.developerExplanation,
    secureAlternative: rule.secureAlternative,
    suggestedFix: rule.suggestedFix,
    threatScenario: rule.threatScenario,
    attackerPerspective: rule.attackerPerspective,
    exploitationReasoning: rule.exploitationReasoning,
    impactAnalysis: rule.impactAnalysis,
    bypassConsiderations: rule.bypassConsiderations,
    manualVerificationChecklist: rule.manualVerificationChecklist,
  };
}
