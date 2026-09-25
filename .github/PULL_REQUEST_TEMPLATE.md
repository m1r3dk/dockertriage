<!--
Thanks for contributing. The checklist is short on purpose: it is the set of
things CI cannot infer and a reviewer should not have to guess.
-->

## What this changes

<!-- One or two sentences. What behaviour is different after this merges? -->

## Why

<!--
The problem, not the patch. If it fixes an issue, link it with "Fixes #123".
-->

## How it was verified

<!--
Name the check and what you observed, not just "tests pass". For anything
touching extraction, say which images you ran it against.
-->

## Checklist

- [ ] `uv run pytest tests/` passes
- [ ] `uv run ruff check src tests` and `uv run ruff format --check src tests` are clean
- [ ] Behaviour changes ship with a test that fails without the fix
- [ ] No new dependency outside `cli.py` (the library stays standard library only)
- [ ] `CHANGELOG.md` updated if this is user-visible
