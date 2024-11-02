import functools
import subprocess

from voltaire_bundler.typing import MempoolId


def p2p_boot(
    p2p_enr_tcp_port: int,
    p2p_enr_udp_port: int,
    p2p_target_peers_number: int,
    p2p_enr_address: str,
    p2p_mempools_ids: list[list[MempoolId]],
    p2p_boot_nodes_enr: str,
    p2p_upnp_enabled: bool,
    p2p_metrics_enabled: bool,
):
    p2p_cmd = [
        "./voltaire-p2p",
        "--enr-tcp-port",
        str(p2p_enr_tcp_port),
        "--enr-udp-port",
        str(p2p_enr_udp_port),
        "--target-peers",
        str(p2p_target_peers_number),
        "--port",
        str(p2p_enr_udp_port),
        "--enable-private-discovery"
    ]
    if p2p_enr_address is not None:
        p2p_cmd.append("--enr-address")
        p2p_cmd.append(p2p_enr_address)
    if len(p2p_mempools_ids) > 0:
        p2p_cmd.append("--p2p-mempool-topic-hashes")
        for topic in functools.reduce(lambda a, b: a + b, p2p_mempools_ids):
            p2p_cmd.append(topic)

    if p2p_boot_nodes_enr is not None:
        p2p_cmd.append("--boot-nodes")
        p2p_cmd.append(p2p_boot_nodes_enr)
    if not p2p_upnp_enabled:
        p2p_cmd.append("--disable-upnp")
    if p2p_metrics_enabled:
        p2p_cmd.append("--p2p_metrics_enabled")

    return subprocess.Popen(p2p_cmd)
