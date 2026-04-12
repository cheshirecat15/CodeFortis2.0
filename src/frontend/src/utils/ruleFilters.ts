import { ruleLibrary } from "../data/ruleLibrary";
import type { OWASPCategory, Rule, SupportedLanguage } from "../types/rules";

export function filterRules(
  language: SupportedLanguage,
  selectedCategories: OWASPCategory[],
): Rule[] {
  // If no categories are selected, return nothing — user explicitly deselected all
  if (selectedCategories.length === 0) return [];

  return ruleLibrary.filter((rule) => {
    const languageMatch = rule.languageScope.includes(language);
    const categoryMatch = selectedCategories.includes(rule.owaspCategory);
    return languageMatch && categoryMatch;
  });
}
