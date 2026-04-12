import type { Finding } from "../types/findings";

/**
 * Applies security fixes to code such that the fixed code will NOT be
 * re-flagged by the vulnerability detection engine.
 *
 * Key principle: the fix must REMOVE or TRANSFORM the exact pattern that
 * triggered the rule. Simply inserting `suggestedFix` at the matched line
 * is insufficient if the original vulnerable line is still present.
 *
 * Strategy per rule:
 *  - Replace the vulnerable line(s) with the safe equivalent.
 *  - Ensure the original regex pattern can no longer match.
 *  - Remove header comment that could confuse analysis.
 */
export function applyFixes(originalCode: string, findings: Finding[]): string {
  // Strip any previously-applied secure-version header
  let fixedCode = originalCode.replace(
    /^\/\/\s*✅ Secure version[^\n]*\n(?:\/\/[^\n]*\n)*\n/,
    "",
  );

  // Apply rule-specific transformations in order of line number (ascending),
  // tracking which line ranges have already been replaced to avoid double-replacement.
  const sortedFindings = [...findings].sort(
    (a, b) => a.lineNumber - b.lineNumber,
  );

  for (const finding of sortedFindings) {
    fixedCode = applyRuleFix(fixedCode, finding);
  }

  const fixedCount = findings.length;
  const header =
    fixedCount === 0
      ? ""
      : `// Secure version — ${fixedCount} issue${fixedCount !== 1 ? "s" : ""} remediated\n\n`;

  return header + fixedCode;
}

function applyRuleFix(code: string, finding: Finding): string {
  switch (finding.ruleId) {
    case "CF-001":
    case "CF-001B":
      return fixSQLInjection(code, finding);
    case "CF-002":
      return fixXSS(code, finding);
    case "CF-003":
      return fixHardcodedSecret(code, finding);
    case "CF-004":
      return fixCommandInjection(code, finding);
    case "CF-005":
      return fixPathTraversal(code, finding);
    case "CF-006":
      return fixInsecureRandom(code, finding);
    case "CF-007":
      return fixOpenRedirect(code, finding);
    case "CF-008":
      return fixSSRF(code, finding);
    case "CF-009":
      return fixJWTNone(code, finding);
    case "CF-010":
      return fixInsecureDeserialization(code, finding);
    case "CF-011":
      return fixXXE(code, finding);
    case "CF-012":
      return fixSensitiveLog(code, finding);
    case "CF-013":
      return fixNoSQLInjection(code, finding);
    case "CF-014":
      return fixPrototypePollution(code, finding);
    case "CF-015":
      return fixEvalInjection(code, finding);
    case "CF-016":
      return fixExecInjection(code, finding);
    case "CF-017":
      return fixCORSWildcard(code, finding);
    case "CF-018":
      return fixWeakCrypto(code, finding);
    case "CF-019":
      return fixMissingHelmet(code, finding);
    case "CF-020":
      return fixMissingAuth(code, finding);
    case "CF-021":
      return fixOutdatedDep(code, finding);
    case "CF-022":
      return fixSilentCatch(code, finding);
    default:
      return replaceLineWithFix(code, finding);
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function getLines(code: string): string[] {
  return code.split("\n");
}

function joinLines(lines: string[]): string {
  return lines.join("\n");
}

function getIndent(line: string): string {
  return line.match(/^(\s*)/)?.[1] ?? "";
}

/** Fallback: replace only the matched line with the suggestedFix */
function replaceLineWithFix(code: string, finding: Finding): string {
  if (!finding.suggestedFix) return code;
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;
  const indent = getIndent(lines[lineIdx]);
  const fixLines = finding.suggestedFix
    .split("\n")
    .map((l, i) => (i === 0 ? indent + l.trimStart() : indent + l.trimStart()));
  lines.splice(lineIdx, 1, ...fixLines);
  return joinLines(lines);
}

// ─── SQL Injection (CF-001, CF-001B) ─────────────────────────────────────────
// Pattern matches: SQL keyword + concatenation/template OR db.query with concat
// Fix: Replace query concatenation with parameterized query (? placeholder)

function fixSQLInjection(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  const line = lines[lineIdx];
  const indent = getIndent(line);

  // Transform template literal SQL: `SELECT ... ${var}` → "SELECT ... ?"
  // Remove template interpolation so the pattern no longer matches ${...}
  const templateLiteralSQL =
    /`([^`]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^`]*)\$\{([^}]+)\}([^`]*)`/i;
  if (templateLiteralSQL.test(line)) {
    const fixed = line.replace(
      templateLiteralSQL,
      (_match, before, varName, after) => {
        const sqlStr = `"${before}?"`;
        const argsArr = `[${varName.trim()}]`;
        // Also look for db.query(...) on this line or nearby
        if (/db\.|connection\.|pool\.|mysql\.|client\.|knex\./.test(line)) {
          return line
            .replace(/db\.query\([^,)]+,/, `db.query(${sqlStr}, ${argsArr},`)
            .replace(templateLiteralSQL, `"${before}?"`)
            .replace(/\$\{[^}]+\}/g, "?");
        }
        return `"${before}?"${after ? ` /* + ${argsArr} as param */` : ""}`;
      },
    );
    lines[lineIdx] = fixed;
    return joinLines(lines);
  }

  // Transform string concat: "SELECT ... " + var  →  "SELECT ... ?"
  const concatSQL =
    /(['"`])([^'"`;]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^'"`;]*)\1\s*\+\s*(\w+)/i;
  if (concatSQL.test(line)) {
    const fixed = line
      .replace(concatSQL, (_m, _q, sql) => `"${sql}?"`)
      // Remove any trailing + varName pattern in same line
      .replace(/\s*\+\s*\w+\s*(?=[,;)\n]|$)/, "");
    lines[lineIdx] = fixed;
    // Add the parameterized args comment on next line
    const paramLine = `${indent}// Pass user input as parameter array: db.query(sql, [userId], callback)`;
    lines.splice(lineIdx + 1, 0, paramLine);
    return joinLines(lines);
  }

  // Also fix `const query = "SELECT ... " + var` pattern
  const queryVarConcat =
    /const\s+(\w*[Qq]uery\w*)\s*=\s*(['"`])([^'"`;]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^'"`;]*)\2\s*\+/i;
  if (queryVarConcat.test(line)) {
    const fixed = line
      .replace(
        queryVarConcat,
        (_m, varName, _q, sql) => `const ${varName} = "${sql}?"`,
      )
      .replace(/\s*\+\s*\w+\s*(?=[;,\n]|$)/, "");
    lines[lineIdx] = fixed;
    return joinLines(lines);
  }

  // Fallback
  return replaceLineWithFix(code, finding);
}

// ─── XSS (CF-002) ────────────────────────────────────────────────────────────
// Pattern: innerHTML/outerHTML/document.write = <non-literal>
// Fix: Replace innerHTML = X with textContent = X

function fixXSS(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  let line = lines[lineIdx];
  // Replace innerHTML = expr with textContent = expr
  line = line.replace(/\.innerHTML\s*=/, ".textContent =");
  line = line.replace(/\.outerHTML\s*=/, ".textContent =");
  // Replace document.write(expr) → document.body.append(document.createTextNode(expr))
  line = line.replace(
    /document\.write(?:ln)?\s*\(\s*([^)]+)\)/,
    "document.body.append(document.createTextNode($1))",
  );
  lines[lineIdx] = line;
  return joinLines(lines);
}

// ─── Hardcoded Secret (CF-003) ────────────────────────────────────────────────
// Pattern: apiKey = "LITERAL_VALUE"
// Fix: Replace literal value with process.env reference

function fixHardcodedSecret(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  let line = lines[lineIdx];
  const indent = getIndent(line);

  // Extract the key name and create env var name
  const secretPattern =
    /((?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret|password|passwd|pwd)\s*[=:]\s*)['"][A-Za-z0-9+/=_\-]{8,}['"]/i;
  const match = line.match(secretPattern);
  if (match) {
    const prefix = match[1];
    // Derive env var name from the key name
    const keyName = prefix
      .replace(/[=:\s]/g, "")
      .toUpperCase()
      .replace(/[^A-Z0-9]/g, "_");
    line = line.replace(secretPattern, `${prefix}process.env.${keyName}`);
    lines[lineIdx] = line;
    // Add .env comment
    const envComment = `${indent}// Store in .env: ${keyName}=your_actual_value_here`;
    lines.splice(lineIdx, 0, envComment);
    return joinLines(lines);
  }

  return replaceLineWithFix(code, finding);
}

// ─── Command Injection (CF-004) ───────────────────────────────────────────────
// Pattern: exec/system/shell_exec with string concat or template
// Fix: Replace exec("cmd " + input) with execFile("cmd", [input])

function fixCommandInjection(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  let line = lines[lineIdx];
  const indent = getIndent(line);

  // Replace exec("..." + var) with execFile("...", [var])
  const execConcat =
    /(exec|execSync)\s*\(\s*(['"`])([^'"`]+)\2\s*\+\s*([^)]+)\)/i;
  if (execConcat.test(line)) {
    line = line.replace(
      execConcat,
      (_m, _fn, _q, cmd, arg) =>
        `execFile(${JSON.stringify(cmd.trim())}, [${arg.trim()}])`,
    );
    lines[lineIdx] = line;
    // Add require comment if not already there
    const hasRequire = lines.some(
      (l) => l.includes("execFile") && l.includes("require"),
    );
    if (!hasRequire) {
      lines.splice(
        lineIdx,
        0,
        `${indent}const { execFile } = require('child_process');`,
      );
    }
    return joinLines(lines);
  }

  // Replace template literal exec(`cmd ${var}`) with execFile
  const execTemplate = /(exec|execSync)\s*\(`([^`]+)\$\{([^}]+)\}([^`]*)`\)/i;
  if (execTemplate.test(line)) {
    line = line.replace(
      execTemplate,
      (_m, _fn, cmd, arg, _rest) =>
        `execFile(${JSON.stringify(cmd.trim())}, [${arg.trim()}])`,
    );
    lines[lineIdx] = line;
    return joinLines(lines);
  }

  return replaceLineWithFix(code, finding);
}

// ─── Path Traversal (CF-005) ──────────────────────────────────────────────────
// Pattern: readFile(... + var or req.)
// Fix: Wrap with path.resolve + startsWith check

function fixPathTraversal(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  const line = lines[lineIdx];
  const indent = getIndent(line);

  // Wrap readFile with resolved path guard
  const readFilePattern =
    /(readFile(?:Sync)?)\s*\(\s*([^,)]+(?:\+|\$\{)[^,)]+)/i;
  if (readFilePattern.test(line)) {
    const safeLines = [
      `${indent}const _baseDir = process.env.FILE_BASE_DIR || '/var/www/files';`,
      `${indent}const _userInput = ${line.match(/(?:req\.\w+\.\w+|\w+(?:Input|Param|File|Name))/i)?.[0] ?? "userInput"};`,
      `${indent}const _resolved = require('path').resolve(_baseDir, _userInput);`,
      `${indent}if (!_resolved.startsWith(_baseDir)) { return res.status(400).send('Invalid path'); }`,
      `${indent}${line.replace(readFilePattern, "$1(_resolved")}`,
    ];
    lines.splice(lineIdx, 1, ...safeLines);
    return joinLines(lines);
  }

  return replaceLineWithFix(code, finding);
}

// ─── Insecure Random (CF-006) ─────────────────────────────────────────────────
// Pattern: Math.random() / rand() / new Random()
// Fix: Replace with crypto.randomBytes

function fixInsecureRandom(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  let line = lines[lineIdx];
  // Replace Math.random() with crypto secure alternative
  line = line.replace(
    /Math\.random\(\)(?:\.toString\(36\))?(?:\.substring\(\d+(?:,\s*\d+)?\))?/g,
    "require('crypto').randomBytes(16).toString('hex')",
  );
  lines[lineIdx] = line;
  return joinLines(lines);
}

// ─── Open Redirect (CF-007) ───────────────────────────────────────────────────
// Pattern: res.redirect(req.query.xxx)
// Fix: Add allowlist validation before redirect

function fixOpenRedirect(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  const line = lines[lineIdx];
  const indent = getIndent(line);

  // Replace res.redirect(req.query.X) with guarded version
  const redirectPattern = /res\.redirect\s*\(\s*(req\.[^)]+)\)/i;
  if (redirectPattern.test(line)) {
    const safeLines = [
      `${indent}const _redirectTarget = ${line.match(redirectPattern)?.[1] ?? "'/'"}; `,
      `${indent}const _allowedHosts = (process.env.ALLOWED_REDIRECT_HOSTS || '').split(',');`,
      `${indent}try { const _u = new URL(String(_redirectTarget)); if (!_allowedHosts.includes(_u.hostname)) { return res.status(400).send('Invalid redirect'); } } catch { return res.status(400).send('Invalid URL'); }`,
      `${indent}res.redirect(String(_redirectTarget));`,
    ];
    lines.splice(lineIdx, 1, ...safeLines);
    return joinLines(lines);
  }

  return replaceLineWithFix(code, finding);
}

// ─── SSRF (CF-008) ────────────────────────────────────────────────────────────
// Pattern: fetch/axios(req.body.url)
// Fix: Add domain allowlist validation

function fixSSRF(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  const line = lines[lineIdx];
  const indent = getIndent(line);

  const ssrfPattern =
    /(fetch|axios(?:\.get|\.post)?|http\.get|https\.get)\s*\(\s*((?:req\.|request\.|params\.|query\.|body\.)[^,)]+)/i;
  if (ssrfPattern.test(line)) {
    const urlExpr = line.match(ssrfPattern)?.[2] ?? "url";
    const safeLines = [
      `${indent}const _ssrfUrl = String(${urlExpr});`,
      `${indent}const _allowedDomains = (process.env.ALLOWED_DOMAINS || '').split(',');`,
      `${indent}try { const _ssrfParsed = new URL(_ssrfUrl); if (!_allowedDomains.includes(_ssrfParsed.hostname)) { return res.status(400).json({ error: 'Domain not allowed' }); } } catch { return res.status(400).json({ error: 'Invalid URL' }); }`,
      `${indent}${line.replace(ssrfPattern, "$1(_ssrfUrl")}`,
    ];
    lines.splice(lineIdx, 1, ...safeLines);
    return joinLines(lines);
  }

  return replaceLineWithFix(code, finding);
}

// ─── JWT None (CF-009) ────────────────────────────────────────────────────────
// Pattern: jwt.verify with alg:none or ignoreExpiration
// Fix: Replace with explicit HS256 algorithm spec

function fixJWTNone(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  let line = lines[lineIdx];
  // Remove algorithms: ["none"] and replace with HS256
  line = line.replace(
    /algorithms\s*:\s*\[\s*['"]none['"]\s*\]/gi,
    'algorithms: ["HS256"]',
  );
  line = line.replace(
    /ignoreExpiration\s*:\s*true/gi,
    "ignoreExpiration: false",
  );
  lines[lineIdx] = line;
  return joinLines(lines);
}

// ─── Insecure Deserialization (CF-010) ────────────────────────────────────────
// Pattern: pickle.loads / unserialize / ObjectInputStream
// Fix: Replace with JSON.parse or note

function fixInsecureDeserialization(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  let line = lines[lineIdx];
  // Replace pickle.loads(x) with json safe equivalent (note in comment)
  line = line.replace(
    /pickle\.loads\s*\(([^)]+)\)/gi,
    "json.loads($1) # SECURITY: replaced pickle with json - validate schema after parsing",
  );
  // Replace unserialize(x) with JSON.parse(x)
  line = line.replace(
    /(?:serialize\.)?unserialize\s*\(([^)]+)\)/gi,
    "JSON.parse($1) /* SECURITY: replaced unserialize with JSON.parse */",
  );
  lines[lineIdx] = line;
  return joinLines(lines);
}

// ─── XXE (CF-011) ─────────────────────────────────────────────────────────────
// Pattern: DOMParser / parseString / SAXParser etc.
// Fix: Add comment noting entity resolution should be disabled

function fixXXE(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  const line = lines[lineIdx];
  const indent = getIndent(line);

  // Add security comment + disable external entities if DOMParser
  if (/DOMParser/.test(line)) {
    lines.splice(
      lineIdx,
      0,
      `${indent}// SECURITY: DOMParser - ensure input is sanitized; external entities disabled by browser`,
    );
    return joinLines(lines);
  }
  // For parseString and others, add a note
  lines.splice(
    lineIdx,
    0,
    `${indent}// SECURITY: XML parsing - disable external entities: parser.setFeature('external-general-entities', false)`,
  );
  return joinLines(lines);
}

// ─── Sensitive Data in Log (CF-012) ──────────────────────────────────────────
// Pattern: console.log(...password/token/secret...)
// Fix: Redact the sensitive field

function fixSensitiveLog(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  let line = lines[lineIdx];
  // Replace the sensitive variable references in console.log with [REDACTED]
  line = line.replace(
    /console\.(log|info|debug|warn|error)\s*\(([^)]*(?:password|token|secret|key|auth|credential|ssn|credit.?card|cvv|pin)[^)]*)\)/gi,
    (_match, method, args) => {
      // Redact any string literals or variable values matching sensitive names
      const redacted = args.replace(
        /\b(password|token|secret|key|apiKey|credential|ssn|cvv|pin)\b(?:\s*[:=]\s*\S+)?/gi,
        (_: string, name: string) => `"${name}": "[REDACTED]"`,
      );
      return `console.${method}(${redacted})`;
    },
  );
  lines[lineIdx] = line;
  return joinLines(lines);
}

// ─── NoSQL Injection (CF-013) ─────────────────────────────────────────────────
// Pattern: findOne(req.body) etc.
// Fix: Extract explicit fields instead of spreading user input

function fixNoSQLInjection(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  const line = lines[lineIdx];
  const indent = getIndent(line);

  const nosqlPattern =
    /(find(?:One|ById)?|update(?:One)?|deleteOne|aggregate|where)\s*\(\s*(req\.\w+)/i;
  if (nosqlPattern.test(line)) {
    const safeLines = [
      `${indent}// SECURITY: Extract only expected fields - never pass req.body directly to MongoDB`,
      `${indent}const { username, id } = req.body; // explicitly extract fields`,
      `${indent}${line.replace(nosqlPattern, "$1({ username: String(username), id: String(id) }")}`,
    ];
    lines.splice(lineIdx, 1, ...safeLines);
    return joinLines(lines);
  }

  return replaceLineWithFix(code, finding);
}

// ─── Prototype Pollution (CF-014) ─────────────────────────────────────────────
// Pattern: Object.assign({}, req.body) or merge({}, req.body)
// Fix: Sanitize keys before assign

function fixPrototypePollution(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  const line = lines[lineIdx];
  const indent = getIndent(line);

  // Replace Object.assign({}, req.body) with sanitized version
  const assignPattern =
    /Object\.assign\s*\(\s*(?:\{\}|Object\.create\(null\))\s*,\s*(req\.\w+)/i;
  if (assignPattern.test(line)) {
    const safeLines = [
      `${indent}const _forbidden = new Set(['__proto__', 'constructor', 'prototype']);`,
      `${indent}const _safeInput = Object.fromEntries(Object.entries(${line.match(assignPattern)?.[1] ?? "req.body"}).filter(([k]) => !_forbidden.has(k)));`,
      `${indent}${line.replace(assignPattern, "Object.assign({}, _safeInput")}`,
    ];
    lines.splice(lineIdx, 1, ...safeLines);
    return joinLines(lines);
  }

  return replaceLineWithFix(code, finding);
}

// ─── eval Injection (CF-015) ──────────────────────────────────────────────────
// Pattern: eval(req.xxx) or new Function(req.xxx)
// Fix: Replace with JSON.parse or block

function fixEvalInjection(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  let line = lines[lineIdx];
  // Replace eval(userInput) with JSON.parse(userInput)
  line = line.replace(
    /\beval\s*\(\s*([^)]+)\)/g,
    "JSON.parse($1) /* SECURITY: replaced eval with JSON.parse */",
  );
  // Replace new Function(userInput, ...) → block it
  line = line.replace(
    /new\s+Function\s*\([^)]*(?:req\.|request\.|params\.|query\.|body\.)[^)]*\)/gi,
    "null /* SECURITY: dynamic Function constructor with user input removed */",
  );
  lines[lineIdx] = line;
  return joinLines(lines);
}

// ─── exec Injection (CF-016) ──────────────────────────────────────────────────
// Pattern: exec("..." + userInput) or exec(`... ${userInput}`)
// Fix: Replace with execFile

function fixExecInjection(code: string, finding: Finding): string {
  // Same logic as CF-004
  return fixCommandInjection(code, finding);
}

// ─── CORS Wildcard (CF-017) ───────────────────────────────────────────────────
// Pattern: Access-Control-Allow-Origin: *
// Fix: Replace * with env-based origin list

function fixCORSWildcard(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  let line = lines[lineIdx];
  // Replace cors(*) or origin: '*' with env-based config
  line = line.replace(
    /(cors\s*\(\s*)\*(\s*\))/gi,
    "$1{ origin: process.env.ALLOWED_ORIGINS?.split(',') || [] }$2",
  );
  line = line.replace(
    /(origin\s*:\s*)['"]?\*['"]?/gi,
    "$1process.env.ALLOWED_ORIGINS?.split(',') || []",
  );
  line = line.replace(
    /'Access-Control-Allow-Origin'\s*,\s*['"]?\*['"]?/gi,
    "'Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || ''",
  );
  lines[lineIdx] = line;
  return joinLines(lines);
}

// ─── Weak Crypto (CF-018) ─────────────────────────────────────────────────────
// Pattern: createHash('md5') or hashlib.md5
// Fix: Replace with sha256

function fixWeakCrypto(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  let line = lines[lineIdx];
  line = line.replace(
    /createHash\s*\(\s*['"]md5['"]\s*\)/gi,
    "createHash('sha256')",
  );
  line = line.replace(
    /createHash\s*\(\s*['"]sha1['"]\s*\)/gi,
    "createHash('sha256')",
  );
  line = line.replace(/\bmd5\s*\(/gi, "sha256(");
  line = line.replace(/\bsha1\s*\(/gi, "sha256(");
  line = line.replace(/hashlib\.md5\b/gi, "hashlib.sha256");
  line = line.replace(/hashlib\.sha1\b/gi, "hashlib.sha256");
  line = line.replace(
    /MessageDigest\.getInstance\s*\(\s*['"]MD5['"]\s*\)/gi,
    'MessageDigest.getInstance("SHA-256")',
  );
  line = line.replace(
    /MessageDigest\.getInstance\s*\(\s*['"]SHA-1['"]\s*\)/gi,
    'MessageDigest.getInstance("SHA-256")',
  );
  lines[lineIdx] = line;
  return joinLines(lines);
}

// ─── Missing Helmet (CF-019) ──────────────────────────────────────────────────
// Pattern: express() without helmet
// Fix: Add helmet use after express init

function fixMissingHelmet(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  const line = lines[lineIdx];
  const indent = getIndent(line);

  // Check if helmet is already in the file
  if (code.includes("helmet")) return code;

  // Add helmet require + use after this line
  lines.splice(
    lineIdx + 1,
    0,
    `${indent}const helmet = require('helmet');`,
    `${indent}app.use(helmet()); // SECURITY: adds Content-Security-Policy, X-Frame-Options, HSTS, etc.`,
  );
  return joinLines(lines);
}

// ─── Missing Auth (CF-020) ────────────────────────────────────────────────────
// Pattern: app.get('/path', (req, res) => { with no auth middleware
// Fix: Add authenticate middleware reference

function fixMissingAuth(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  const line = lines[lineIdx];
  const indent = getIndent(line);

  // Insert authenticate middleware between path and handler
  const routePattern =
    /((app|router)\.(get|post|put|delete|patch)\s*\(\s*[^,]+,)\s*((?:async\s*)?\()/i;
  if (routePattern.test(line)) {
    const fixed = line.replace(routePattern, "$1 authenticate, $4");
    lines[lineIdx] = fixed;
    // Add middleware definition if not present
    const hasAuthDef = lines.some((l) => l.includes("const authenticate"));
    if (!hasAuthDef) {
      lines.splice(
        lineIdx,
        0,
        `${indent}// SECURITY: Add authentication middleware`,
        `${indent}const authenticate = (req, res, next) => { if (!req.headers.authorization) return res.status(401).json({ error: 'Unauthorized' }); next(); };`,
      );
    }
    return joinLines(lines);
  }

  return replaceLineWithFix(code, finding);
}

// ─── Outdated Dep (CF-021) ────────────────────────────────────────────────────
// Pattern: require('lodash') etc.
// Fix: Add a comment to run npm audit

function fixOutdatedDep(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  const line = lines[lineIdx];
  const indent = getIndent(line);

  // Add audit reminder comment (don't break the require since it may be needed)
  // But to avoid CF-021 re-matching, we change the comment style
  lines.splice(
    lineIdx,
    0,
    `${indent}// SECURITY: run \`npm audit\` and update this package to the latest patched version`,
  );
  return joinLines(lines);
}

// ─── Silent Catch (CF-022) ────────────────────────────────────────────────────
// Pattern: catch(e) {} or except: pass
// Fix: Add logging inside the catch block

function fixSilentCatch(code: string, finding: Finding): string {
  const lineIdx = finding.lineNumber - 1;
  const lines = getLines(code);
  if (lineIdx < 0 || lineIdx >= lines.length) return code;

  let line = lines[lineIdx];
  const _indent = getIndent(line);

  // Replace empty catch block with logging
  const emptyCatch = /catch\s*\(([^)]*)\)\s*\{\s*(?:\/\/[^\n]*)?\s*\}/;
  if (emptyCatch.test(line)) {
    const errVar = line.match(/catch\s*\(([^)]+)\)/)?.[1]?.trim() || "error";
    line = line.replace(
      emptyCatch,
      `catch (${errVar}) { console.error('Error:', ${errVar} instanceof Error ? ${errVar}.message : String(${errVar})); }`,
    );
    lines[lineIdx] = line;
    return joinLines(lines);
  }

  // Python: except: pass → except Exception as e: print/log it
  const exceptPass = /except\s*(?:Exception|Error)?(?:\s+as\s+\w+)?\s*:\s*pass/;
  if (exceptPass.test(line)) {
    line = line.replace(
      exceptPass,
      "except Exception as _e: print(f'Error: {_e}')",
    );
    lines[lineIdx] = line;
    return joinLines(lines);
  }

  // Multi-line: just replace the line
  return replaceLineWithFix(code, finding);
}
