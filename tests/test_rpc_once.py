"""send_rpc_request_once: one attempt, result or RpcRequestError, and no
log output of its own (callers with periodic probes own the log policy)."""
from __future__ import annotations

import json
from contextlib import asynccontextmanager

import pytest

import voltaire_bundler.utils.eth_client_utils as ecu
from voltaire_bundler.utils.eth_client_utils import (
    RpcRequestError,
    send_rpc_request_once,
)


class FakeResponse:
    def __init__(self, status: int, body: bytes):
        self.status = status
        self._body = body

    async def read(self) -> bytes:
        return self._body


class FakeSession:
    """``post`` yields the queued (status, body) or raises the queued
    exception."""

    def __init__(self, outcome):
        self.outcome = outcome
        self.requests: list[dict] = []

    @asynccontextmanager
    async def post(self, url, json=None, headers=None):
        self.requests.append(json)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        status, body = self.outcome
        yield FakeResponse(status, body)


def _use(monkeypatch, outcome) -> FakeSession:
    session = FakeSession(outcome)
    monkeypatch.setattr(ecu, "get_eth_client_session", lambda: session)
    return session


@pytest.mark.asyncio
async def test_returns_result(monkeypatch, caplog):
    session = _use(monkeypatch, (200, json.dumps(
        {"jsonrpc": "2.0", "id": 1, "result": "0x10"}).encode()))
    caplog.set_level("DEBUG")

    assert await send_rpc_request_once("http://a", "eth_gasPrice") == "0x10"
    assert session.requests == [
        {"jsonrpc": "2.0", "id": 1, "method": "eth_gasPrice", "params": None}
    ]
    assert caplog.records == []


@pytest.mark.parametrize("outcome, needle", [
    (ConnectionError("refused"), "eth_gasPrice: ConnectionError"),
    (TimeoutError(), "eth_gasPrice: TimeoutError()"),
    ((429, b"rate limited"), "HTTP 429"),
    ((200, b"<html>"), "invalid JSON"),
    ((200, b"[1]"), "unexpected response"),
    ((200, json.dumps({"error": {"code": -32005, "message": "limit"}}).encode()),
     "node error -32005: limit"),
    ((200, json.dumps({"jsonrpc": "2.0", "id": 1}).encode()), "without result"),
])
@pytest.mark.asyncio
async def test_failures_raise_one_line_errors_and_log_nothing(
    monkeypatch, caplog, outcome, needle
):
    _use(monkeypatch, outcome)
    caplog.set_level("DEBUG")

    with pytest.raises(RpcRequestError) as excinfo:
        await send_rpc_request_once("http://a", "eth_gasPrice")

    assert needle in str(excinfo.value)
    assert "\n" not in str(excinfo.value)
    assert caplog.records == []
