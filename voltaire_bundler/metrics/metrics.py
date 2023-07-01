import logging
from prometheus_client import start_http_server

def run_metrics_server(port=8000):
    logging.info(f"Starting Metrics Server at: {port}")
    start_http_server(port)