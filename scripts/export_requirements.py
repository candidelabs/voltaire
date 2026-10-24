import subprocess


def export():
    # Sync poetry.lock with pyproject.toml, then export the pinned (hashed)
    # requirements.txt that the Dockerfile installs from that lock.
    # Needs the export plugin: poetry self add poetry-plugin-export
    subprocess.run(["poetry", "lock"], check=True)
    subprocess.run(
        ["poetry", "export", "-f", "requirements.txt",
         "--output", "requirements.txt"],
        check=True,
    )
