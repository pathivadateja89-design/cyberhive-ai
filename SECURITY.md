# Security notes and threat model

## Security boundary

This prototype is designed to inspect user-provided source as inert text in the current browser tab. It does not execute submitted code, make target or repository requests, send source to a server/provider, or claim to verify permission. The user must have the source owner's explicit written permission and must exclude credentials, production secrets, personal data, and any code they are not authorized to share.

An on-screen checkbox records only the user's assertion. It is not evidence of ownership or a legal determination. Do not use the demo to scan live targets or to treat a heuristic result as a vulnerability verdict.

## Published cybersecurity-use policy

Use this tool only for source you own or have explicit written authorization to share and review. The authorization must cover every submitted file. An on-screen attestation records an assertion; the prototype does not prove that you have the rights claimed.

- No live-target use: this app cannot probe domains, URLs, IPs, network services, or repositories. Do not repurpose it to bypass controls, access information, or disrupt services.
- Minimize disclosure: do not submit API keys, passwords, private keys, live production secrets, customer records, or personal data. Use sanitized code or synthetic samples.
- Stay in scope: provide only names included in the project's attested, exact-file allowlist. Stop if permission, source rights, or scope are uncertain.
- Handle results responsibly: a match is an unverified pattern, not a vulnerability verdict. A clean review does not establish security. Do not take disruptive remediation actions based only on this tool.
- Report safely: this prototype has no monitored incident or vulnerability-reporting channel. Never include confidential source or credentials in a public message or issue.

This use policy describes the expected behavior for the demonstration; it is not legal advice, a compliance certification, or an assurance that self-attestation has been independently verified.

## Browser and hosting protections

The public static site is hosted on GitHub Pages at <https://pathivadateja89-design.github.io/cyberhive-ai/>. GitHub Pages serves this repository's public site files; GitHub's policies govern its hosting and request processing. HTTPS enforcement is enabled, and the live response includes a `Strict-Transport-Security` header. The app has no backend, and its source analyzer does not transmit submitted code.

`index.html` includes a Content Security Policy that allows only same-origin scripts and styles, disables connections, objects, and HTML form submissions, and restricts referrer disclosure to `no-referrer`. Existing CSS style attributes are permitted for UI presentation. This meta-delivered policy cannot provide response-header directives such as `frame-ancestors`. GitHub Pages is static hosting and does not offer project-level configuration of arbitrary security response headers; do not assume framing protection or other server-header controls that the host has not independently confirmed. Keep the browser policy restrictive and avoid claiming a security certification.

## Assets and threats

| Asset | Threat | Current mitigation / limitation |
| --- | --- | --- |
| User-provided source | Unintended upload or execution | Source is read with browser text APIs and matched as strings; the MVP has no scanner network client, source-upload API, AI integration, or code execution. |
| Authorized scope | User selects a file outside their asserted scope | Project registration requires explicit attestation and simple exact supported basenames. A separate review attestation is required, and submitted filenames must exactly match a subset of the registered list. The app cannot validate the truth of either assertion. |
| Browser availability | Oversized, binary, or excessive input uses memory/CPU | File-count, per-file and total byte, NUL-byte, and 50,000-line limits; line-by-line processing; cooperative yield and cancellation. |
| Review results | A heuristic is mistaken for a confirmed vulnerability or a clean bill of health | Results are labeled provisional/unverified with human review required; demo fixtures are separately labeled synthetic; the UI and report describe important limitations. |
| Browser DOM | Malicious code snippets or filenames become executable markup | Dynamic content uses DOM text nodes/`textContent`, not HTML parsing. Submitted source is not interpreted as a script. |
| Credentials and user data | A user provides secrets, sensitive data, or a credential-bearing repository URL | The trust UI instructs users not to provide secrets or personal data. Repository references are labels only; credential-bearing, query-bearing, fragment-bearing, and non-HTTPS web URLs are rejected. Do not treat client-side rules as a guarantee that secrets cannot be entered. |

## Known limitations and residual risk

- Permission is self-attested and not independently verified; filenames do not prove a user's rights.
- Heuristics are incomplete, line-oriented, and can miss issues or produce false positives. They do not build syntax trees, trace data flow, resolve dependencies, prove exploitability, or establish security.
- All projects, attestations, reviews, and findings are transient page memory, not durable records. There is no user isolation or authentication.
- A local browser can be affected by browser extensions, a compromised device, or modified page scripts. This static app does not defend a device or browser.
- Client-side input caps are reliability controls, not a hostile multi-tenant service boundary.
- The UI intentionally offers no live scan, repository fetch, AI review, or persistent agent. Future implementation of those features requires a separate threat model and architecture.
- Individual and Team subscription concepts have no prices, do not accept sign-ups, and are not for sale. There is no payment or account functionality.

## Safe handling guidance

Only review source you are expressly authorized to provide. Use redacted, non-production material and synthetic credentials in demos. Keep secrets, private keys, personal data, and live customer data out of source input. Confirm every reported line against surrounding code and project-specific context; never deploy a change solely because this tool suggested it.

## Verification

Open `tests.html` in a modern browser to run the analyzer checks locally. They cover heuristic matches, benign/placeholder examples, file limits and rejection, line numbers, safe source handling, and cancellation. These checks do not establish authorization, assess a deployed website, or prove the absence of vulnerabilities.
