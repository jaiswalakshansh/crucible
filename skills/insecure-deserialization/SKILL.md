---
name: insecure-deserialization
description: Untrusted data deserialized by an unsafe deserializer, enabling object injection / RCE.
rule_id: crucible.insecure-deserialization
cwe: CWE-502
severity: high
technique: taint
activation: ["scan for insecure deserialization", "check pickle/yaml load safety"]
---

# Insecure Deserialization

## Recon
Find unsafe deserialization sinks fed by input: `pickle.loads`, `cPickle`,
`yaml.load` (without `SafeLoader`), `marshal.loads`, `jsonpickle.decode`,
`dill.loads`, Java `ObjectInputStream`. Sources: request bodies, cookies, cache
entries, message payloads.

## Verify (false-positive reduction)
1. Is the deserializer actually unsafe? `yaml.safe_load`, `json.loads`, and
   `pickle` on trusted-only data are not this bug.
2. Is the serialized blob attacker-controlled (not signed/HMAC-verified first)?
3. Signed/verified payloads (e.g. itsdangerous) before deserialization are safe.

## Evidence
Source→sink path and the deserializer call. Note: an RCE PoC for pickle is
constructible (a `__reduce__` gadget) but Crucible does not auto-run it against a
live app; the finding stays suspected unless proven.
