---
name: xxe
description: Untrusted XML parsed with external entities enabled, allowing file read / SSRF.
rule_id: crucible.xxe
cwe: CWE-611
severity: high
technique: taint
activation: ["scan for xxe", "check xml parser safety"]
---

# XML External Entity (XXE)

## Recon
Find XML parse sinks fed by input: `etree.parse/fromstring`, `minidom.parse`,
`sax.parse`, DOM/SAX parsers. Sources: request bodies, uploaded files, SOAP.

## Verify (false-positive reduction)
1. Is the parser configured to resolve external entities/DTDs? Modern `defusedxml`
   or parsers with entity resolution disabled are safe.
2. Is the XML attacker-controlled?

## Evidence
Source→sink path and the parser call. Payload sketch: a `<!DOCTYPE>` with a
`SYSTEM "file:///etc/passwd"` entity.
