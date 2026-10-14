"use strict";

(function registerCyberHiveEngine() {
  const LIMITS = Object.freeze({
    maxFiles: 15,
    maxFileBytes: 524288,
    maxTotalBytes: 2097152,
    maxTotalLines: 50000,
    maxSnippetCharacters: 200
  });

  const ALLOWED_EXTENSIONS = new Set([
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".java", ".go",
    ".rb", ".php", ".cs", ".c", ".h", ".cpp", ".hpp", ".rs", ".swift",
    ".kt", ".html", ".htm", ".css", ".scss", ".sql", ".json", ".yaml",
    ".yml", ".toml", ".sh", ".xml", ".vue", ".svelte", ".md", ".txt"
  ]);

  const PLACEHOLDER_SECRET = /(?:placeholder|example|sample|dummy|fake|changeme|change[_-]?me|test(?:ing)?[_-]?key|your[_-].*key|replace[_-]?me|not[_-]?a[_-]?secret|redacted|\*{4,})/i;

  const RULES = Object.freeze([
    {
      id: "hardcoded-credential",
      title: "Potential hard-coded credential",
      severity: "High",
      confidence: 8,
      category: "Secrets handling",
      cwe: "CWE-798",
      matches(line) {
        const match = line.match(/\b(?:api[_-]?key|client[_-]?secret|secret[_-]?key|password|passwd|access[_-]?token|private[_-]?key)\b\s*[:=]\s*(?:"([^"\r\n]{8,})"|'([^'\r\n]{8,})')/i);
        if (!match) return false;
        const value = match[1] || match[2] || "";
        return !PLACEHOLDER_SECRET.test(value) && !/^\$[{(]/.test(value) && !/^(?:<|%[A-Z0-9_]+%|\$\{)/i.test(value);
      },
      summary: "A credential-like field appears to have a string literal assigned to it. A test fixture or placeholder can also match this heuristic.",
      remediation: "Check whether this is a real credential. Remove real secrets from source, rotate exposed values through the owner's process, and load secrets from an approved secrets manager or protected environment."
    },
    {
      id: "dynamic-sql",
      title: "Potentially unsafe SQL construction",
      severity: "High",
      confidence: 7,
      category: "Input handling",
      cwe: "CWE-89",
      matches(line) {
        const hasQueryCall = /\b(?:query|execute|exec|raw|run)\s*\(/i.test(line);
        const buildsDynamicQuery = /(?:\+\s*(?:req(?:uest)?|params?|input|userInput)\b|`[^`]*\$\{\s*(?:req(?:uest)?|params?|input|userInput)\b|\bformat\s*\([^)]*(?:req(?:uest)?|params?|input)\b)/i.test(line)
          || /(?:req(?:uest)?\.(?:query|params|body)|params?\.[a-z_$][\w$]*)/.test(line);
        const includesQueryText = /\b(?:select|insert|update|delete|where)\b/i.test(line);
        return hasQueryCall && buildsDynamicQuery && includesQueryText;
      },
      summary: "A SQL-like operation and request-derived value occur in the same source line. The use of parameterized queries cannot be inferred from this text-only check.",
      remediation: "Verify how the query is parameterized and how input reaches this call. Prefer your database driver's documented bound-parameter API, preserve authorization checks, and test only with approved, synthetic data."
    },
    {
      id: "dynamic-command",
      title: "Potentially unsafe command construction",
      severity: "High",
      confidence: 7,
      category: "Input handling",
      cwe: "CWE-78",
      matches(line) {
        const invokesProcess = /\b(?:exec|execSync|spawn|spawnSync|system|popen)\s*\(/i.test(line)
          || /os\.system\s*\(/i.test(line);
        const incorporatesInput = /(?:\+|\$\{)\s*(?:req(?:uest)?|params?|input|userInput|form|data)\b|(?:req(?:uest)?\.(?:query|params|body)|params?\.[a-z_$][\w$]*)/i.test(line);
        return invokesProcess && incorporatesInput;
      },
      summary: "A process-execution API and a request-derived value appear on the same line. The check does not execute commands or prove that input is attacker-controlled.",
      remediation: "Check whether external input reaches a process invocation. Avoid constructing shell command strings; prefer a fixed executable and separate, validated arguments, with an explicit allowlist and least privilege."
    },
    {
      id: "dynamic-html",
      title: "Potential unsafe dynamic HTML",
      severity: "Medium",
      confidence: 6,
      category: "Output encoding",
      cwe: "CWE-79",
      matches(line) {
        const includesHtmlSink = /\.innerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML\b|\.\s*html\s*\(/i.test(line);
        const includesDynamicValue = /(?:\+|\$\{|\.value\b|request\.(?:body|query|params)|req\.(?:body|query|params)|userInput|userContent|dangerouslySetInnerHTML)/i.test(line);
        return includesHtmlSink && includesDynamicValue;
      },
      summary: "A dynamic-looking value and an HTML rendering sink appear together. This heuristic cannot determine whether output is safely encoded or the value is trusted.",
      remediation: "Trace the value's source and encoding. Prefer framework text rendering or context-appropriate escaping; sanitize permitted markup with a maintained allowlist-based sanitizer."
    },
    {
      id: "dynamic-code",
      title: "Dynamic code execution",
      severity: "High",
      confidence: 8,
      category: "Execution safety",
      cwe: "CWE-95",
      matches(line) {
        return /\b(?:eval|new\s+Function|Function)\s*\(/.test(line);
      },
      summary: "A dynamic JavaScript code-construction API appears on this line. The presence of the API alone does not establish an exploitable data flow.",
      remediation: "Check why dynamic evaluation is needed, how its input is controlled, and whether the behavior can use a typed parser or explicit operation map instead."
    },
    {
      id: "permissive-cors",
      title: "Review permissive CORS configuration",
      severity: "Medium",
      confidence: 7,
      category: "Web configuration",
      cwe: "CWE-942",
      matches(line) {
        return /(?:access-control-allow-origin|origin)\s*["']?\s*[:=]\s*["']\*["']|access-control-allow-origin\s*:\s*\*/i.test(line);
      },
      summary: "This line appears to allow a wildcard cross-origin origin. The check cannot determine whether this is a test fixture or how credentialed requests are configured.",
      remediation: "Confirm the production CORS policy and its relationship to credentials. Restrict browser origins to the application owner's explicit allowlist."
    },
    {
      id: "disabled-tls-validation",
      title: "TLS certificate validation may be disabled",
      severity: "High",
      confidence: 8,
      category: "Transport security",
      cwe: "CWE-295",
      matches(line) {
        return /rejectUnauthorized\s*:\s*false\b|(?:verify|ssl_verify)\s*=\s*False\b|ssl_verify\s*[:=]\s*0\b/i.test(line);
      },
      summary: "A familiar client setting appears to disable TLS certificate validation. A test-only configuration can also match.",
      remediation: "Check which environment uses this setting and restore normal certificate verification. For local tests, trust the intended test certificate instead of disabling peer verification."
    }
  ]);

  function validateFiles(files) {
    if (!Array.isArray(files) || files.length === 0) {
      throw new Error("Add at least one source file or paste authorized source text.");
    }
    if (files.length > LIMITS.maxFiles) {
      throw new Error(`Select no more than ${LIMITS.maxFiles} files in one review.`);
    }

    let totalBytes = 0;
    let totalLines = 0;
    const normalized = files.map((file) => {
      if (!file || typeof file.name !== "string" || typeof file.content !== "string") {
        throw new Error("Each review item must have a filename and text content.");
      }
      const name = file.name.trim();
      const baseName = name.split(/[\\/]/).pop();
      if (!baseName || baseName.startsWith(".") || /[\u0000-\u001f\u007f]/.test(baseName)) {
        throw new Error("Hidden, empty, or invalid filenames are not accepted.");
      }
      const lastDot = baseName.lastIndexOf(".");
      const extension = lastDot >= 0 ? baseName.slice(lastDot).toLowerCase() : "";
      if (!ALLOWED_EXTENSIONS.has(extension)) {
        throw new Error(`“${baseName.slice(0, 80)}” is not a supported text file. Select source or text configuration files only.`);
      }
      if (file.content.includes("\u0000")) {
        throw new Error(`“${baseName.slice(0, 80)}” contains binary data and cannot be reviewed as text.`);
      }

      const bytes = new TextEncoder().encode(file.content).length;
      if (bytes > LIMITS.maxFileBytes) {
        throw new Error(`“${baseName.slice(0, 80)}” exceeds the 512 KB per-file review limit.`);
      }
      totalBytes += bytes;
      totalLines += 1 + (file.content.match(/\n/g) || []).length;
      return { name: baseName, content: file.content, bytes };
    });

    if (totalBytes > LIMITS.maxTotalBytes) {
      throw new Error("The supplied source exceeds the 2 MB total review limit.");
    }
    if (totalLines > LIMITS.maxTotalLines) {
      throw new Error("The supplied source exceeds the 50,000 line review limit. Split it into a smaller, explicitly authorized review.");
    }

    return { files: normalized, totalLines };
  }

  async function analyzeFiles(files, options = {}) {
    const { files: normalized, totalLines } = validateFiles(files);
    const findings = [];
    const onProgress = typeof options.onProgress === "function" ? options.onProgress : () => {};
    const signal = options.signal;
    let bytesReviewed = 0;
    let linesReviewed = 0;

    for (let index = 0; index < normalized.length; index += 1) {
      if (signal && signal.aborted) throw new DOMException("Review cancelled.", "AbortError");

      const file = normalized[index];
      onProgress({
        phase: "Inspecting source text",
        filesCompleted: index,
        filesTotal: normalized.length,
        bytesReviewed,
        totalBytes: normalized.reduce((total, item) => total + item.bytes, 0)
      });

      const lines = file.content.split(/\r?\n/);
      for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
        if (signal && signal.aborted) throw new DOMException("Review cancelled.", "AbortError");

        const line = lines[lineIndex].trim();
        if (line) {
          for (const rule of RULES) {
            if (!rule.matches(line)) continue;
            findings.push(Object.freeze({
              id: `${rule.id}:${file.name}:${lineIndex + 1}`,
              ruleId: rule.id,
              title: rule.title,
              severity: rule.severity,
              confidence: rule.confidence,
              category: rule.category,
              cwe: rule.cwe,
              projectType: "local",
              source: "local",
              verified: false,
              status: "Needs human review",
              filename: file.name,
              line: lineIndex + 1,
              snippet: line.length > LIMITS.maxSnippetCharacters
                ? `${line.slice(0, LIMITS.maxSnippetCharacters - 1)}…`
                : line,
              summary: rule.summary,
              remediation: rule.remediation
            }));
          }
        }
        linesReviewed += 1;
        if (lineIndex % 256 === 255) {
          onProgress({
            phase: "Inspecting source text",
            filesCompleted: index,
            filesTotal: normalized.length,
            linesReviewed,
            totalLines,
            bytesReviewed,
            totalBytes: normalized.reduce((total, item) => total + item.bytes, 0)
          });
          await new Promise((resolve) => window.setTimeout(resolve, 0));
        }
      }

      bytesReviewed += file.bytes;
      if (signal && signal.aborted) throw new DOMException("Review cancelled.", "AbortError");
      if (index < normalized.length - 1) await new Promise((resolve) => window.setTimeout(resolve, 0));
    }

    onProgress({
      phase: "Source review complete",
      filesCompleted: normalized.length,
      filesTotal: normalized.length,
      linesReviewed,
      totalLines,
      bytesReviewed,
      totalBytes: bytesReviewed
    });

    return Object.freeze({
      filesReviewed: normalized.length,
      bytesReviewed,
      linesReviewed: totalLines,
      findings: Object.freeze(findings),
      outcome: findings.length
        ? "Review possible patterns with a developer; human verification is required, and none are verified."
        : "No supported patterns were identified by these limited checks. This is not evidence that the source is secure."
    });
  }

  window.CyberHiveEngine = Object.freeze({
    limits: LIMITS,
    allowedExtensions: Object.freeze([...ALLOWED_EXTENSIONS]),
    ruleIds: Object.freeze(RULES.map((rule) => rule.id)),
    validateFiles,
    analyzeFiles
  });
})();
