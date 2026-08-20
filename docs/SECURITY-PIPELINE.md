# Security pipeline

This repository is scanned by [secure-pipeline][sp], called as a reusable
workflow from `.github/workflows/security.yml`. Policy is centralized there;
this repository owns only `.security/exceptions.yaml`.

[sp]: https://github.com/rdx0120/secure-pipeline

## The first run failed, and that is the finding

On first contact the pipeline returned **exit 2 — coverage failure — with zero
findings blocked**:

```
LEG       UNIT                      EXAMINED  OF  FLOOR  FINDINGS  STATUS
bandit    python_files_on_disk      15        15  1      46        PASS
gitleaks  commits                   6         6   1      0         PASS
semgrep   python_files_git_tracked  15        15  1      0         PASS
trivy-fs  resolvable_packages       0         0   1      0         FAIL

  trivy-fs: FAIL_NO_COVERAGE
  [dependency resolution] 0 packages resolvable.
                          Nothing resolves -- SCA is a no-op reporting success.

VERDICT: COVERAGE FAILURE  (exit 2)
```

Nothing was blocked. No vulnerable dependency was found. The build is red
because **the dependency scanner examined nothing and would have reported
success either way.** This repository declares its dependencies in
`pyproject.toml` without a lockfile, so there is nothing for the scanner to
resolve to a concrete version — and an empty findings list from a scanner that
looked at zero packages is indistinguishable, in the findings channel alone,
from a clean bill of health.

That distinction is the entire reason the pipeline emits a coverage attestation
alongside its findings.

**This was not patched around.** No lockfile was added to make the run go green,
and the floor was not lowered. A pipeline built around one repository meeting a
second one and immediately surfacing a real blind spot is the evidence that the
design generalises; making the symptom disappear would have destroyed that
evidence and left the blind spot.

## Fixing it properly

Committing a lockfile (`uv lock`) makes the dependencies resolvable, at which
point the SCA leg reports a real number — and a zero-vulnerability result
becomes a *verified* zero rather than an unexamined one.

## What passes today

`bandit`, `gitleaks` and `semgrep` all clear their floors and examine their full
populations. The 46 bandit findings are `B101` asserts in the test suite, below
the configured floor for that tool, so they neither block nor warn.

Note that `semgrep` reports zero findings against the custom
`unbounded-binary-read` rule, which was written specifically for this
repository's arena parser. That is a genuine true negative: the parser validates
its buffer table against `len(data)` and checks `pos + 8 > len(data)` before each
relocation read. It was confirmed by reading the parser and by a three-variant
probe proving the rule *could* fire — not by trusting the rule's silence.
