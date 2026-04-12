export interface SyntaxIssue {
  line: number;
  type: "unbalanced_brackets" | "unclosed_string" | "unclosed_block";
  message: string;
}

export interface SyntaxCheckResult {
  errors: SyntaxIssue[];
  fixedCode: string;
}

export function checkSyntax(code: string): SyntaxCheckResult {
  const errors: SyntaxIssue[] = [];
  const lines = code.split("\n");

  let braces = 0;
  let parens = 0;
  let brackets = 0;
  let braceOpenLine = -1;
  let parenOpenLine = -1;
  let bracketOpenLine = -1;

  // Simple string-aware bracket counting (skip chars inside strings)
  let inSingleQuote = false;
  let inDoubleQuote = false;
  let inBacktick = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (let ci = 0; ci < line.length; ci++) {
      const ch = line[ci];
      const prev = ci > 0 ? line[ci - 1] : "";

      // Handle escape sequences
      if (prev === "\\") continue;

      // Toggle string modes
      if (ch === "'" && !inDoubleQuote && !inBacktick) {
        inSingleQuote = !inSingleQuote;
        continue;
      }
      if (ch === '"' && !inSingleQuote && !inBacktick) {
        inDoubleQuote = !inDoubleQuote;
        continue;
      }
      if (ch === "`" && !inSingleQuote && !inDoubleQuote) {
        inBacktick = !inBacktick;
        continue;
      }

      // Skip bracket counting inside strings
      if (inSingleQuote || inDoubleQuote || inBacktick) continue;

      if (ch === "{") {
        if (braces === 0) braceOpenLine = i + 1;
        braces++;
      } else if (ch === "}") {
        braces--;
        if (braces < 0) {
          errors.push({
            line: i + 1,
            type: "unbalanced_brackets",
            message: `Unexpected '}' on line ${i + 1}`,
          });
          braces = 0;
        }
      } else if (ch === "(") {
        if (parens === 0) parenOpenLine = i + 1;
        parens++;
      } else if (ch === ")") {
        parens--;
        if (parens < 0) {
          errors.push({
            line: i + 1,
            type: "unbalanced_brackets",
            message: `Unexpected ')' on line ${i + 1}`,
          });
          parens = 0;
        }
      } else if (ch === "[") {
        if (brackets === 0) bracketOpenLine = i + 1;
        brackets++;
      } else if (ch === "]") {
        brackets--;
        if (brackets < 0) {
          errors.push({
            line: i + 1,
            type: "unbalanced_brackets",
            message: `Unexpected ']' on line ${i + 1}`,
          });
          brackets = 0;
        }
      }
    }
    // Strings don't span lines (simplification — good enough for static hints)
    inSingleQuote = false;
    inDoubleQuote = false;
    // backtick template literals CAN span lines, leave inBacktick as-is
  }

  if (braces > 0)
    errors.push({
      line: braceOpenLine,
      type: "unbalanced_brackets",
      message: `${braces} unclosed '{' — opened near line ${braceOpenLine}`,
    });
  if (parens > 0)
    errors.push({
      line: parenOpenLine,
      type: "unbalanced_brackets",
      message: `${parens} unclosed '(' — opened near line ${parenOpenLine}`,
    });
  if (brackets > 0)
    errors.push({
      line: bracketOpenLine,
      type: "unbalanced_brackets",
      message: `${brackets} unclosed '[' — opened near line ${bracketOpenLine}`,
    });

  // Generate fixed code by appending missing closing chars
  let fixedCode = code;
  if (braces > 0) fixedCode += `\n${Array(braces + 1).join("}")}`;
  if (parens > 0) fixedCode += Array(parens + 1).join(")");
  if (brackets > 0) fixedCode += Array(brackets + 1).join("]");

  return { errors, fixedCode };
}
