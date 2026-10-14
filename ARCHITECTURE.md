# Architecture

## Current browser-only prototype

| File | Responsibility |
| --- | --- |
| `index.html` | Single-page application markup, demo disclosure, navigation, exact-scope inputs, permission attestations, and local result views. |
| `styles.css` | Responsive dark operations dashboard and its permission, demo, review, results, and project states. |
| `app.js` | Hash routes, synthetic demo data, session-memory projects and results, scope enforcement, File API reads, progress/cancellation, findings UI, and local report download. |
| `security-engine.js` | Pure text validation and deterministic line-oriented heuristics; exports `window.CyberHiveEngine`. |
| `tests.html`, `tests.css`, `tests.js` | Browser-native tests for analyzer matches, safe examples, input bounds, line references, and cancellation. |

The app uses plain HTML, CSS, and JavaScript with no package dependencies or build pipeline. The deferred analyzer script loads before the deferred application script. Browser `File.text()` reads only explicitly selected files; pasted source is read from its text area. Neither path transmits source or executes it. The findings UI inserts dynamic filenames, labels, source excerpts, and guidance through DOM `textContent` or element construction. Report export creates a browser-local Markdown Blob.

The page applies a restrictive meta-delivered Content Security Policy: scripts and styles load from this origin, style attributes are allowed for existing in-app visual indicators, connections are disabled, embedded objects are disallowed, and the page cannot submit form data. It also opts out of referrer transmission. A static meta policy cannot set response-only protections such as HSTS or `frame-ancestors`; a deployment host must configure suitable response headers separately.

## Scope and review flow

The person registering a project attests to written permission and enters a comma-separated allowlist of exact, supported basenames. A review requires a second, per-review attestation. The submitted review scope must be a subset of the registered filenames and match the supplied upload/paste filenames exactly. Pasted source has a predictable name (`pasted-source.[language]`) and must be authorized as such. This UI does not verify that a user owns a project or that their claims are true.

The analyzer rejects unsupported or hidden filenames, NUL-byte content, over-limit files, too many files, over-limit combined source, and source exceeding the line bound before inspecting text. Seven heuristics inspect each source line and retain its basename and 1-based line number. Work yields periodically so the user can cancel. A cancellation produces no findings or assessment record.

## Synthetic presentation data

The dashboard's example projects, findings, counts, activity, assessment history, and 320-role specialist roster are code-defined presentation fixtures. They are never outputs of the local analyzer. Reserved `.invalid` names and visible simulation labels reinforce the boundary. Only reviews initiated from explicit browser-local input create real session-memory results.

## Deliberately unimplemented

There is no server, authentication, account, tenant, persistent data store, API, repository integration, AI provider, scanner, dependency feed, job queue, agent, audit log, billing, or deployment pipeline. Project and assessment data disappear on reload. Reports are user-triggered downloads made in the browser.

There is no payment provider, checkout, recurring billing, paid entitlement, published offer, price, or sales contact form. The current demo is available for free; proposed Individual and Team plans have no confirmed pricing or availability.

## Future integration boundary

Any future repository or live-target capability would need separately designed backend authorization verification, tenant-scoped access controls, file/object isolation, per-job exact target enforcement, durable and revocable consent records, audit logging, abuse/rate controls, restricted network egress, bounded workloads, cancellation, secrets management, security testing, and human review. It must not be inferred from or silently added to this static prototype.
