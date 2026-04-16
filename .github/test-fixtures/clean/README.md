# Aguara test fixture (clean)

This directory is consumed by `.github/workflows/test-action.yml` to verify
that the action exits with code 0 when scanning content that has no findings
above the configured `fail-on` threshold.

The content here is intentionally generic prose so that no Aguara rule across
any layer (pattern, NLP, toxicflow, rugpull) produces findings. If a future
rule starts matching this file, replace the offending wording rather than
disabling the rule.
