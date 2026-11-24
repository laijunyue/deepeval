# deepeval HumanEval: secure_exec sandbox escape leads to RCE

## Summary

deepeval's HumanEval benchmark executes Python returned by the model under test. secure_exec() claims a sandbox but only swaps __builtins__ for an allow-list, leaving dunder attribute access and __subclasses__() open. HumanEval.predict() concatenates the untrusted completion with benchmark test code and calls secure_exec(), so a malicious or prompt-injected model runs OS commands as the deepeval process.

## Details

Root cause: secure_exec() (deepeval/benchmarks/human_eval/human_eval.py:14-83) restricts only __builtins__ names (lines 22-73) before compile()/exec() (lines 78-80); attribute access (__class__, __base__, __subclasses__, __globals__) stays unrestricted and getattr/type remain exposed (lines 60-63), so the allow-list is bypassable by construction. Trust-boundary failure: HumanEval.predict() takes each completion of model.generate_samples() verbatim (lines 199-201), builds full_code = function + newline + golden.expected_output (line 205) and executes it (line 206). Chain: (1) model output 199-201; (2) concatenation 205; (3) sink exec at line 80; (4) escape via ().__class__.__base__.__subclasses__() -> _wrap_close.__init__.__globals__[sys].modules[os] -> os.system(). except Exception: pass at 208-211 hides failures and the counter still increments, so a compromise looks like a normal run.

Core vulnerable code path:

```python
# deepeval/benchmarks/human_eval/human_eval.py:203-206
for function in functions:
                try:
                    full_code = function + "\n" + golden.expected_output
                    secure_exec(full_code)
```

Untrusted model completion is concatenated with benchmark test code and passed straight into the exec sink, with no validation or isolation.

```python
# deepeval/benchmarks/human_eval/human_eval.py:76-81
try:
        # Compile the code first to validate syntax
        compiled_code = compile(code_str, "<string>", "exec")
        # Execute with restricted environment
        exec(compiled_code, safe_globals, local_vars)
        return local_vars
```

exec() of attacker-influenced source in the evaluator process; safe_globals is only a builtins name allow-list, so object-graph traversal reaches the real os module.

## POC

No deepeval HTTP endpoint is involved; the payload arrives in the model completion (for OpenAI-compatible judges, the chat-completions response whose content becomes an element of functions). Preconditions: victim runs HumanEval().evaluate(model) and the model output is attacker-controlled, from a third-party endpoint, or prompt-injected. Step 1: the model returns a valid solve() stub followed by escape statements walking ().__class__.__base__.__subclasses__(), picking _wrap_close, reading __init__.__globals__[sys].modules[os] and calling os.system('id'). Step 2: the victim runs the benchmark; deepeval builds full_code and calls secure_exec(full_code). Expected result: commands execute in the evaluation process. In this audit the real secure_exec was extracted from the repository and executed with that payload, printing uid=0(root) gid=0(root) groups=0(root) while the run still reported an accuracy score.

## Impact

Arbitrary code execution on the evaluation host (developer machine, CI runner or internal eval server holding model keys, cloud credentials and source code): reading any file the user can read, executing binaries, reaching internal services, persisting a backdoor, and fabricating benchmark results.

## Remediation

Do not execute model code in the evaluator process; use a short-lived sandbox (low-privilege subprocess with seccomp, throwaway container, gVisor) without network. If an in-process sandbox remains, enforce AST restrictions (no dunder attribute/subscript access, no __subclasses__/__globals__/__builtins__/import) via RestrictedPython and never expose getattr/type/hasattr. Remove the broad except Exception: pass at human_eval.py:208-211, add per-sample timeouts, and make code execution opt-in. Add a regression test with standard escape payloads.

## Disclosure Notes

Found by source review of snapshot commit 7185807 (main) and confirmed by executing the repository's own secure_exec with an escape payload. No CVE ID assigned and no fixed version confirmed, so patched_versions is to be confirmed; contact the confident-ai/deepeval maintainers privately first (90-day window or until a patched release). Until then run HumanEval in an isolated container without credentials.

## Supplemental Information

### Affected products

- Ecosystem: pypi
- Package name: deepeval
- Affected versions: main branch (snapshot commit 7185807); releases shipping deepeval/benchmarks/human_eval/human_eval.py with secure_exec
- Patched versions: to be confirmed

### Severity

- Scoring method: CVSS v3.1
- Score: 9.6
- Vector string: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H

### Weaknesses

- CWE: CWE-94: Improper Control of Generation of Code ('Code Injection'); CWE-693: Protection Mechanism Failure
