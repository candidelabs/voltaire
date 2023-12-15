import os

def build():
    cmd ="".join([
        "cd voltaire_p2p &&",
        "cargo build --release --target x86_64-unknown-linux-musl &&",
        "cp target/x86_64-unknown-linux-musl/release/voltaire-p2p ..",
    ])
    os.system(cmd)