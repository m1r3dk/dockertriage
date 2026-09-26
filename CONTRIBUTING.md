# Contributing

Thanks for looking. Bug reports with a reproducing image reference are the
most useful thing you can send; correctness fixes with a test are the next.

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
Security problems go through [SECURITY.md](SECURITY.md), not a public issue.

## Ground rules

These are the constraints that define the product. A change that breaks one
of them is a different tool, so each is enforced by CI rather than by review:

1. Every module under `src/dockertriage/` except `cli.py` stays Python 3.14+
   standard library only, and `import dockertriage` must not pull in Typer.
   Someone embedding the library should not pay for a CLI they never call.
2. `src/dockertriage/cli.py` is the only module allowed third-party imports,
   and it is the only CLI. There used to be two, kept in sync by hand, and
   they drifted. Do not add a second one.
3. No Docker daemon, no root. The tool must run anywhere with nothing
   installed.
4. Every correctness fix ships with a test that fails without it.
5. The test suite stays offline. Tests fake the registry; nothing in
   `tests/` may reach the network, so the suite is deterministic and works
   on a plane. `tests/verify_against_crane.py` is the deliberate exception
   and is not part of the default run.

## Getting set up

```bash
git clone https://github.com/m1r3dk/dockertriage
cd dockertriage
uv sync                    # installs the package plus the dev group
uv run pytest tests/       # should be green before you change anything
```

Without uv, `pip install -e .` first: the `src/` layout means the package has
to be installed before the tests can import it.

## Running the tests

```bash
uv run pytest tests/                        # everything
uv run python tests/test_dockertriage.py    # library modules
uv run python tests/test_cli.py             # the CLI
```

To prove your change did not quietly introduce a network call, run the suite
with sockets blocked. It should still pass:

```bash
cat > /tmp/sitecustomize.py <<'EOF'
import socket
def _no(*a, **k): raise RuntimeError("test tried to use the network")
socket.socket.connect = _no
socket.create_connection = _no
EOF
PYTHONPATH=/tmp uv run python -m pytest tests/ -q
```

Ground truth against `crane` needs the network and the `crane` binary. This
is what catches dropped symlinks and hardlinks, which unit tests alone cannot
prove:

```bash
uv run python tests/verify_against_crane.py alpine:3.19 debian:bookworm-slim
```

## Before you open a pull request

```bash
uv run ruff check src tests
uv run ruff format --check src tests
uv run pytest tests/
```

Update `CHANGELOG.md` under `[Unreleased]` if the change is user-visible.

## A note on output

This tool writes extracted container filesystems to disk. Those are large,
are not ours to redistribute, and routinely contain credentials the image
author committed by accident. `.gitignore` covers the default output paths,
but check `git status` before committing: a stray `output/` or an analysis
folder must never end up in a commit.

## Style

Whatever `ruff` in `pyproject.toml` says. Beyond that: comments should
explain *why*, especially where the code looks odd because a registry or a
tar file behaves badly. Several non-obvious branches exist because a real
image broke a reasonable assumption, and saying which one saves the next
person an afternoon.

## Commits

Conventional Commits: `feat:`, `fix:`, `docs:`, `test:`, `chore:`. Write the
body for someone trying to understand the change a year from now.
