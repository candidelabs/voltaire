import logging
from prometheus_client import start_http_server


def run_metrics_server(host="localhost", port=8000):
    """
    run prometheus metrics server
    """
    logging.info(f"Starting Metrics Http Server at: {host}:{port}")
    start_http_server(port)
