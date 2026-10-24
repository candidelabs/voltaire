import subprocess
import sys

# Only bounds the quick `--help` preflight; `poetry lock` can legitimately
# take minutes while resolving.
PREFLIGHT_TIMEOUT_S = 30


def export():
    # `poetry export` is provided by a plugin that Poetry 2.x doesn't bundle.
    # It is declared under [tool.poetry.requires-plugins]; fail early with a
    # clear message if it hasn't been installed yet.
    try:
        plugin_check = subprocess.run(
            ["poetry", "export", "--help"],
            capture_output=True,
            timeout=PREFLIGHT_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        sys.exit(
            f"`poetry export --help` did not finish within "
            f"{PREFLIGHT_TIMEOUT_S}s; check your Poetry installation."
        )
    if plugin_check.returncode != 0:
        sys.exit(
            "poetry-plugin-export is not installed. Run `poetry install` "
            "(or `poetry self add poetry-plugin-export`) and retry."
        )

    # Sync poetry.lock with pyproject.toml, then export the pinned (hashed)
    # requirements.txt that the Dockerfile installs from that lock.
    subprocess.run(["poetry", "lock"], check=True)
    subprocess.run(
        ["poetry", "export", "-f", "requirements.txt",
         "--output", "requirements.txt"],
        check=True,
    )
