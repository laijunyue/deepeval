# deepeval prompt JINJA interpolation renders remote templates with an unsandboxed jinja2 Template (SSTI to RCE)

## Summary

deepeval stores the prompt text and interpolation type returned by the Confident AI prompt API without validation. When the type is JINJA, Prompt.interpolate() routes the text to interpolate_jinja(), which compiles and renders it with a default, unsandboxed jinja2.Template. A template is data but is executed here, so anyone able to write or poison that prompt can run arbitrary commands on the developer machine or CI runner that renders it. The TypeScript SDK has no JINJA branch, so the surface exists only in the Python SDK.

## Details

Root cause: JINJA interpolation treats template text as code. deepeval/prompt/utils.py:81-83 implements interpolate_jinja as jinja2.Template(text).render(**kwargs) - a default Environment, not SandboxedEnvironment - so every Jinja expression is evaluated with access to Python attribute chains and globals such as cycler. interpolate_text() (prompt/utils.py:86-99) selects this branch from interpolation_type alone, a value that comes from data rather than code.

Trust-boundary failure: the template is not authored by the rendering code. Prompt.pull() builds PromptHttpResponse from the Confident AI response (prompt.py:642-655), taking text from data.get('text') and interpolation_type from data['interpolationType'], and stores both (lines 670-678). Documented usage is Prompt(alias=...).pull() then Prompt.interpolate(), which dispatches at prompt.py:234-247 to interpolate_text(interpolation_type, text_template, **kwargs). Whoever can edit that prompt therefore chooses the renderer and supplies its source.

Chain: (1) remote prompt record prompt.py:642-678; (2) Prompt.interpolate() prompt.py:234-247; (3) JINJA branch prompt/utils.py:98-99; (4) interpolate_jinja() prompt/utils.py:81-83 where Template(text).render() evaluates attacker expressions. Prompt.load() (prompt.py:198-211) gives the same entry from a local .txt/.json prompt file. typescript/src/prompt/utils.ts implements only the four regex modes and throws otherwise, so JINJA execution was never an intended cross-SDK feature.

Core vulnerable code path:

```python
# deepeval/prompt/prompt.py:674-678
self.text_template = response.text
                self.messages_template = response.messages
                self._prompt_id = response.id
                self.type = response.type
                self.interpolation_type = response.interpolation_type
```

Source of the template: body and interpolation type come from the Confident AI response and are stored on the Prompt without validation or signing.

```python
# deepeval/prompt/utils.py:81-83
def interpolate_jinja(text: str, **kwargs: Any) -> str:
    template = Template(text)
    return template.render(**kwargs)
```

Sink: default, unsandboxed jinja2 Template compiled from template text and rendered, so Jinja expressions reach Python globals and can run commands.

## POC

The victim uses no deepeval HTTP endpoint: the payload is the prompt pulled from the Confident AI prompt API (HTTPS GET with the CONFIDENT-API-KEY header) or loaded with Prompt.load().

Preconditions: the attacker can create or modify the prompt used by the victim project with interpolationType JINJA; the victim calls prompt.interpolate(...).

Step 1: attacker sets text to a Jinja expression such as the cycler globals os.popen id expression and interpolationType to JINJA. Expected: the platform stores it and the SDK persists both verbatim (prompt.py:674-678).

Step 2: victim runs p = Prompt(alias="victim"); p.pull(); print(p.interpolate(input="hi")). Expected: interpolate() dispatches through interpolate_text() into interpolate_jinja(), the expression is evaluated on the client host, and the rendered prompt contains command output such as uid=0(root) gid=0(root), i.e. code execution with the privileges of the Python process.

Step 3 (sink check): rendering the same string with jinja2.Template(...).render() reproduces the output, showing the renderer has no sandbox.

## Impact

Arbitrary command execution on the machine or CI runner that renders a poisoned prompt. The SDK runs in CI pipelines and services holding model provider keys and Confident AI credentials, so an attacker who can influence prompt content (low-privileged project member, shared/imported prompt, poisoned prompt file) gains code execution on other developers' hosts and build agents, enabling credential theft, source-code exfiltration and supply-chain tampering.

## Remediation

1) Use jinja2.sandbox.SandboxedEnvironment, or remove JINJA interpolation to match the TypeScript SDK, which supports only regex modes and rejects JINJA. 2) Treat prompts fetched from Confident AI as untrusted data: default to a data-only interpolation type and require explicit opt-in for template engines. 3) Restrict dangerous attributes, filters and globals when a template engine is used. 4) Sign or version prompts so clients can detect tampering. 5) Add a regression test asserting that cycler globals expressions cannot be evaluated.

## Disclosure Notes

Found by source review of snapshot commit 7185807 (main). The code chain is fully established, but exploitation requires the attacker to write the target prompt (project member with prompt write access, shared/imported prompt, or poisoned prompt file); that permission model is unverified, so this is reported as a candidate. No CVE ID assigned and no fixed version confirmed, patched_versions is to be confirmed; contact the maintainers privately first.

## Supplemental Information

### Affected products

- Ecosystem: pypi
- Package name: deepeval
- Affected versions: main branch (snapshot commit 7185807); releases shipping deepeval/prompt/utils.py with the JINJA branch
- Patched versions: to be confirmed

### Severity

- Scoring method: CVSS v3.1
- Score: 8.0
- Vector string: CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H

### Weaknesses

- CWE: CWE-1336: Improper Neutralization of Template Engine Syntax; CWE-94: Improper Control of Generation of Code ('Code Injection')
