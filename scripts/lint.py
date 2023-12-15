import subprocess                                                               

def start():
    cmd =';'.join(
        [
            "echo Flake8:",
            'flake8 --extend-select',
            "echo Mypy:",
            'mypy voltaire_bundler'
        ])
    subprocess.run(cmd, shell=True)