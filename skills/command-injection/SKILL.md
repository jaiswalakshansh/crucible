---
name: command-injection
description: Untrusted input reaching an OS command execution sink without safe argument handling.
rule_id: crucible.command-injection
cwe: CWE-78
severity: high
technique: taint
activation: ["scan for command injection", "check shell execution safety"]
---

# Command Injection

## Recon
Find where external input reaches a command sink: `os.system`, `subprocess.*`
(especially `shell=True`), `os.popen`, backticks, `child_process.exec`.
Sources: request params/body/headers, CLI args, env, file contents.

## Verify (false-positive reduction)
1. Is the input actually attacker-controlled at runtime, or constant/internal?
2. Is a shell involved? `subprocess.run([...], shell=False)` with a list argument
   is generally safe — argument boundaries are preserved. `shell=True` or string
   concatenation into the command is dangerous.
3. Is the tainted value used as the command/program, or as data passed safely?
4. Any sanitizer on the path (`shlex.quote`, allow-list)?

Only forward findings where attacker input can alter the command executed.

## Evidence
Concrete source→sink path (file:line per hop), the sink expression, and a minimal
injection payload for the PoC gate (e.g. `; id`, `$(id)`). Do not claim
confirmation — that status is set only when a PoC actually fires.
