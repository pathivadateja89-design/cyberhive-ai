"use strict";

(async function runCyberHiveTests() {
  const output = document.getElementById("test-results");
  const status = document.getElementById("test-status");
  const results = [];

  function record(name, ok, detail = "") {
    results.push({ name, ok, detail });
    const row = document.createElement("li");
    row.textContent = `${ok ? "PASS" : "FAIL"} — ${name}${detail ? ` — ${detail}` : ""}`;
    row.className = ok ? "test-result-pass" : "test-result-fail";
    output.append(row);
  }

  function assert(condition, name, detail = "") {
    record(name, Boolean(condition), detail);
    if (!condition) throw new Error(detail || name);
  }

  async function assertRejects(work, includes, name) {
    try {
      await work();
      record(name, false, "Expected the source check to reject this input.");
    } catch (error) {
      record(name, error instanceof Error && error.message.includes(includes), error instanceof Error ? error.message : String(error));
    }
  }

  const engine = window.CyberHiveEngine;
  if (!engine || typeof engine.analyzeFiles !== "function") {
    status.textContent = "FAIL — CyberHiveEngine failed to load.";
    return;
  }

  const safeFile = {
    name: "notes.js",
    content: [
      "const query = 'SELECT id FROM users WHERE id = ?';",
      "database.query(query, [userId]);",
      "element.textContent = userProvidedName;",
      "const accessToken = process.env.ACCESS_TOKEN;"
    ].join("\n")
  };
  const originalSafeContent = safeFile.content;

  try {
    const findings = await engine.analyzeFiles([
      { name: "credentials.js", content: 'const PASSWORD = "real-looking-development-password-92841";\nconst API_KEY = "test-key-placeholder";' },
      { name: "unsafe-query.js", content: 'const rows = db.query("SELECT * FROM accounts WHERE id = " + request.query.id);' },
      { name: "unsafe-command.py", content: 'os.system("lookup " + request.args["host"])' },
      { name: "unsafe-render.js", content: "panel.innerHTML = request.body.displayName;" },
      { name: "unsafe-runtime.js", content: "const result = eval(codeFromInput);" },
      { name: "tls.py", content: "response = request.get(url, verify=False)" },
      { name: "cors.json", content: '"origin": "*"' },
      safeFile
    ]);

    assert(findings.filesReviewed === 8, "Reads each explicitly supplied text file.");
    assert(findings.linesReviewed === 12, "Counts source lines read without executing them.");
    assert(findings.findings.length === 7, "Flags credential, query, command, HTML, runtime-evaluation, TLS, and wildcard-CORS patterns.");
    assert(findings.findings.every((finding) => finding.verified === false && finding.status === "Needs human review"), "Marks every pattern as unverified and requiring human review.");
    assert(findings.findings.find((finding) => finding.ruleId === "dynamic-sql")?.filename === "unsafe-query.js", "Preserves the corresponding source filename.");
    assert(findings.findings.find((finding) => finding.ruleId === "dynamic-sql")?.line === 1, "Preserves the exact 1-based source line.");
    assert(findings.findings.find((finding) => finding.ruleId === "dynamic-sql")?.severity === "High", "Provides conservative heuristic severity, not a CVSS claim.");
    assert(!findings.findings.some((finding) => finding.ruleId === "hardcoded-credential" && finding.filename === "credentials.js" && finding.line === 2), "Excludes conspicuously labeled test placeholders.");
    assert(findings.findings.some((finding) => finding.ruleId === "permissive-cors"), "Flags wildcard CORS for explicit configuration review.");
    assert(findings.findings.every((finding) => finding.snippet.length <= engine.limits.maxSnippetCharacters), "Bounds every reported source excerpt.");
    assert(safeFile.content === originalSafeContent, "Reads but does not mutate submitted source.");
    assert(findings.outcome.includes("human"), "Clearly describes human review as required.");

    const executionProbe = "__cyberHiveAnalyzerExecutionProbe";
    window[executionProbe] = false;
    await engine.analyzeFiles([{
      name: "inert-input.js",
      content: "window.__cyberHiveAnalyzerExecutionProbe = true;"
    }]);
    assert(window[executionProbe] === false, "Treats supplied code as inert text rather than executing it.");
    delete window[executionProbe];

    let completionProgress;
    await engine.analyzeFiles([{ name: "progress.js", content: "one\ntwo\nthree" }], {
      onProgress(progress) {
        if (progress.phase === "Source review complete") completionProgress = progress;
      }
    });
    assert(
      completionProgress?.linesReviewed === 3 && completionProgress?.totalLines === 3,
      "Reports final reviewed-line totals consistently."
    );

    const benign = await engine.analyzeFiles([safeFile]);
    assert(benign.findings.length === 0, "Does not flag parameterized queries, text rendering, or environment-provided credentials in a benign sample.");

    await assertRejects(
      () => engine.analyzeFiles([{ name: ".env", content: "ACCESS_TOKEN=hidden" }]),
      "Hidden, empty, or invalid filenames",
      "Refuses environment-secret and hidden files."
    );
    await assertRejects(
      () => engine.analyzeFiles([{ name: "archive.zip", content: "PK\u0003\u0004" }]),
      "not a supported text file",
      "Refuses archives and unsupported binary file formats."
    );
    await assertRejects(
      () => engine.analyzeFiles([{ name: "bad.js", content: "source\u0000binary" }]),
      "binary data",
      "Refuses binary or NUL-byte source."
    );
    await assertRejects(
      () => engine.analyzeFiles(Array.from({ length: engine.limits.maxFiles + 1 }, (_, index) => ({ name: `part-${index}.js`, content: "" }))),
      "no more than 15 files",
      "Rejects an excessive source-file count."
    );
    await assertRejects(
      () => engine.analyzeFiles([{ name: "large.js", content: "x".repeat(engine.limits.maxFileBytes + 1) }]),
      "per-file review limit",
      "Enforces the 512 KB individual-file limit."
    );
    await assertRejects(
      () => engine.analyzeFiles(Array.from({ length: 4 }, (_, index) => ({ name: `part-${index}.js`, content: "x".repeat(engine.limits.maxFileBytes) })).concat([{ name: "part-extra.js", content: "x" }])),
      "2 MB total",
      "Enforces the 2 MB total-source limit."
    );
    await assertRejects(
      () => engine.analyzeFiles([{ name: "too-many-lines.js", content: "\n".repeat(engine.limits.maxTotalLines) }]),
      "50,000 line",
      "Bounds total source lines for browser safety."
    );
    await assertRejects(
      () => engine.analyzeFiles([{ name: "good.js", content: "const ok = true;" }], { signal: AbortSignal.abort() }),
      "cancelled",
      "Stops a cancelled review before inspecting files."
    );

    const controller = new AbortController();
    let yielded = false;
    await assertRejects(
      () => engine.analyzeFiles([{ name: "responsive.js", content: "const sample = true;\n".repeat(1200) }], {
        signal: controller.signal,
        onProgress(progress) {
          if (!yielded && progress.linesReviewed >= 256) {
            yielded = true;
            controller.abort();
          }
        }
      }),
      "cancelled",
      "Yields while processing long source files so cancellation remains responsive."
    );
    assert(yielded, "Reports review progress during a long source file.");

    assert(
      !engine.allowedExtensions.includes(".zip") && !engine.allowedExtensions.includes(".env"),
      "Keeps archives and environment-secret files out of the supported file list."
    );
    const totals = [48, 64, 48, 36, 24, 24, 28, 18, 16, 14].reduce((sum, count) => sum + count, 0);
    assert(totals === 320, "Confirms the UI-only specialist roster totals exactly 320 simulated role slots.");

    status.textContent = `${results.filter((result) => result.ok).length} browser checks passed; ${results.filter((result) => !result.ok).length} failed. No uploads or live scans were made.`;
    status.dataset.state = results.every((result) => result.ok) ? "pass" : "fail";
    document.documentElement.dataset.testResult = results.every((result) => result.ok) ? "pass" : "fail";
  } catch (error) {
    status.textContent = `Test runner interrupted: ${error instanceof Error ? error.message : String(error)}`;
    status.dataset.state = "fail";
    document.documentElement.dataset.testResult = "fail";
  }
})();
