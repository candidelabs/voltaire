import subprocess


def start():
    cmd = ';'.join(
        [
            "echo Flake8:",
            'flake8',
            "echo Mypy:",
            'mypy voltaire_bundler'
        ])
    subprocess.run(cmd, shell=True)
