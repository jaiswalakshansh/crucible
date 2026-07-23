---
name: dom-xss
description: Untrusted browser input reaching a DOM HTML sink without escaping.
rule_id: crucible.dom-xss
cwe: CWE-79
severity: high
technique: taint
activation: ["scan for dom xss", "check innerHTML safety"]
---

# DOM-Based XSS

## Recon
Sources: `location.search/hash/href`, `document.URL/cookie/referrer`,
`window.name`, `postMessage` data. Sinks: assignment to `innerHTML`/`outerHTML`,
`dangerouslySetInnerHTML`, `document.write`, `insertAdjacentHTML`, `eval`.

## Verify (false-positive reduction)
1. Is the value inserted as HTML, or as text (`textContent`, escaped)? Text is safe.
2. Is it sanitized (DOMPurify, an allow-list) before insertion?
3. Is the source genuinely attacker-influenced?

## Evidence
Source→sink path and the sink (call or assignment target). Payload sketch:
`<img src=x onerror=alert(1)>`.
