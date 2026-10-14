# CyberHive AI · authorization-first security demo

CyberHive AI is a static browser prototype for reviewing source files that a user says they are authorized to share. Register a project with an exact filename allowlist, attest to written permission, select or paste only those files, and run deterministic, line-oriented text checks entirely in the browser.

**The 320 specialist-role roster, projects, activity, findings, and assessment history on the dashboard are illustrative demo data. There are zero running agents.** The source-review flow is real but limited: its heuristic matches are provisional, can be false positives, do not trace code paths, and cannot establish that code is secure.

## Run it

No build step, package installation, account, API key, or server is required. Open `index.html` in a modern browser. To run the automated analyzer checks, open `tests.html`; a successful run displays its total in the page and sets `document.documentElement.dataset.testResult` to `pass`.

## Public demo

The static site is published on GitHub Pages at <https://pathivadateja89-design.github.io/cyberhive-ai/>. The public repository also exposes the site's source code and documentation. GitHub Pages serves the files; the app itself has no server-side analyzer, account system, analytics, or payment processing.

## Run a local review

1. From **Projects**, add a project and list the exact authorized source-file basenames (for example, `auth.js, auth.test.js`). Project registration is an attestation, not an ownership or permission check.
2. From **Source review**, select that project and keep the requested filenames within its registered list.
3. Upload those files or paste source. Pasted text is named `pasted-source.[language]`; include that exact name in the project authorization before scanning it. After selecting or editing the source and scope, affirm permission for that specific review immediately before starting it.
4. Review every possible match in context. No match is not proof of security. Findings are unverified and must be reviewed by an authorized developer.

Paths, wildcards, environment files, archives, and unsupported extensions are rejected. Limits are 15 source files, 512 KiB per file, 2 MiB combined, and 50,000 source lines per review. The browser keeps projects, findings, and review history in page memory only; reloading clears them.

## What is and is not included

The included analyzer checks a small set of code lines for credential-like literals, SQL or shell-command construction, dynamic HTML, dynamic code evaluation, wildcard CORS, and disabled TLS validation. It reports a heuristic severity label, CWE reference, source excerpt, and review guidance. These are simple text heuristics—not data-flow analysis, a CVSS score, verified vulnerabilities, or a substitute for professional assessment.

This prototype does **not** fetch or clone repositories, probe URLs/IPs/services, access dependency databases, execute submitted source, upload source, call AI providers, run background jobs, validate authorization, provide accounts or tenant isolation, or persist to a backend/database. The repository reference is a non-fetching display label only. Local state and assessment results disappear on reload.

## Security policy and proposed plans

The **Trust & scope** page explains the authorization-first cybersecurity-use policy and the prototype's privacy and hosting limitations. The app ships a restrictive browser Content Security Policy: only same-origin scripts and styles can load, application network connections are blocked, and objects and form submissions are disabled. The inline policy is not a replacement for hosting response headers or a comprehensive security assessment.

**Plans & pricing** is a proposed, non-binding product roadmap—not a live offer. The existing browser-only demo is free. Individual and Team tiers have no prices or availability, their future feature descriptions are proposals, and there is no checkout, subscription, or payment processing.

For limitations, local test coverage, and security assumptions, see [ARCHITECTURE.md](ARCHITECTURE.md) and [SECURITY.md](SECURITY.md).
