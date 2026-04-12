export type DetectableLang =
  | "javascript"
  | "typescript"
  | "python"
  | "java"
  | "php"
  | "go"
  | "csharp";

export function detectCodeLanguage(code: string): DetectableLang | null {
  const pythonScore = (
    code.match(/\bdef \w+\s*\(|import \w+|from \w+ import|print\(|#[^\n]/g) ||
    []
  ).length;
  const javaScore = (
    code.match(
      /public class|public static void|System\.out\.|import java\.|@Override/g,
    ) || []
  ).length;
  const phpScore = (
    code.match(/<\?php|\$[a-zA-Z_]|\becho\b|\$_GET|\$_POST/g) || []
  ).length;
  const goScore = (
    code.match(/\bfunc \w+\s*\(|:=|package main|import \(|fmt\./g) || []
  ).length;
  const csharpScore = (
    code.match(
      /using System|Console\.Write|namespace \w+|\.cs\b|public class.*\{/g,
    ) || []
  ).length;
  // TypeScript gets a boost to differentiate from plain JS
  const tsScore = (
    code.match(
      /:\s*(string|number|boolean|void|any|never)\b|interface \w+|<[A-Z]\w*>|import .* from ['"]|type \w+ =|enum \w+/g,
    ) || []
  ).length;
  const jsScore = (
    code.match(/\bconst \b|\blet \b|\bvar \b|require\(|module\.exports|=>/g) ||
    []
  ).length;

  const scores: [DetectableLang, number][] = [
    ["python", pythonScore],
    ["java", javaScore],
    ["php", phpScore],
    ["go", goScore],
    ["csharp", csharpScore],
    ["typescript", tsScore * 1.5],
    ["javascript", jsScore],
  ];

  scores.sort((a, b) => b[1] - a[1]);
  const top = scores[0];
  if (top[1] < 2) return null; // not enough signal
  return top[0];
}

export function getLanguageLabel(lang: DetectableLang | string): string {
  const labels: Record<string, string> = {
    javascript: "JavaScript",
    typescript: "TypeScript",
    python: "Python",
    java: "Java",
    php: "PHP",
    go: "Go",
    csharp: "C#",
  };
  return labels[lang] ?? lang;
}
