---
name: path-traversal
description: Untrusted input used to build a filesystem path, allowing access outside the intended directory.
rule_id: crucible.path-traversal
cwe: CWE-22
severity: high
technique: taint
activation: ["scan for path traversal", "check file path safety"]
---

# Path Traversal

## Recon
Find file sinks whose path is influenced by input: `open`, `os.open`,
`send_file`, `send_from_directory`, template/static file loaders. Sources:
filename params, upload names, archive entry names.

## Verify (false-positive reduction)
1. Can the input contain `..`, absolute paths, or NUL bytes?
2. Is the path canonicalized and checked to stay within a base dir
   (`os.path.realpath` + prefix check), or reduced to `os.path.basename` /
   `secure_filename`? Those neutralize traversal.
3. Is the base directory attacker-influenced too?

## Evidence
Source→sink path, the path-building expression, and any sanitizer. Payload sketch
for the PoC gate: `../../etc/passwd`.
