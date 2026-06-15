"""
Tests for the eth_getLogs "missing block data" short-circuit in
``send_rpc_request_to_eth_client``.

A node that has pruned a block range (or hasn't synced it yet) will
return ``{"error": {"code": ..., "message": "...missing block data..."}}``
for an eth_getLogs query. The default retry loop runs up to 60 × 1 s
sleeps, which is pure waste: the data isn't going to materialise inside
that window. The helper must surface the error response immediately so
the caller (which treats a result-less response as a miss) can move on.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from voltaire_bundler.utils import eth_client_utils
from voltaire_bundler.utils.eth_client_utils import (
    send_rpc_request_to_eth_client,
)


NODE_URL = "http://node.invalid"


class _FakeResponse:
    """Mimic just enough of aiohttp's response context-manager surface
    for the helper's ``async with session.post(...)`` block."""

    def __init__(self, body: bytes, status: int = 200):
        self._body = body
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def read(self):
        return self._body


def _session_returning(bodies):
    """Build an aiohttp-ish session whose ``post()`` returns successive
    response bodies. Each call to ``post`` advances by one body so a
    test can assert how many round trips happened."""
    iterator = iter(bodies)

    def _post(*_args, **_kwargs):
        try:
            body = next(iterator)
        except StopIteration:
            raise AssertionError(
                "send_rpc_request_to_eth_client retried more times than "
                "the test had responses queued — short-circuit is broken"
            )
        return _FakeResponse(body)

    session = MagicMock()
    session.post = MagicMock(side_effect=_post)
    return session


@pytest.fixture
def no_sleep():
    """Skip the real ``asyncio.sleep(1)`` between retry attempts so a
    test that expects N retries finishes in milliseconds, not N seconds.
    Without this the suite would hang for a full minute on any
    regression that re-enables the retry loop."""
    with patch.object(eth_client_utils.asyncio, "sleep", AsyncMock()):
        yield


@pytest.mark.asyncio
async def test_eth_getLogs_missing_block_data_returns_immediately(no_sleep):
    """One round trip → error response surfaced; no retries."""
    body = (
        b'{"jsonrpc":"2.0","id":1,'
        b'"error":{"code":-32000,"message":"missing block data"}}'
    )
    session = _session_returning([body])
    with patch.object(eth_client_utils, "get_eth_client_session",
                      return_value=session):
        result = await send_rpc_request_to_eth_client(
            [NODE_URL], "eth_getLogs", params=[{}],
        )
    assert result["error"]["message"] == "missing block data"
    assert session.post.call_count == 1, (
        "missing-block-data must short-circuit the retry loop"
    )


@pytest.mark.asyncio
async def test_short_circuit_is_case_insensitive(no_sleep):
    """Different providers capitalise the message differently
    ("Missing block data" / "MISSING BLOCK DATA" / nested into a longer
    sentence); the check must be substring-and-case-insensitive."""
    body = (
        b'{"jsonrpc":"2.0","id":1,'
        b'"error":{"code":-32000,"message":'
        b'"Range exceeded: Missing Block Data at block 12345"}}'
    )
    session = _session_returning([body])
    with patch.object(eth_client_utils, "get_eth_client_session",
                      return_value=session):
        await send_rpc_request_to_eth_client(
            [NODE_URL], "eth_getLogs", params=[{}],
        )
    assert session.post.call_count == 1


@pytest.mark.asyncio
async def test_other_eth_getLogs_errors_still_retry(no_sleep):
    """Non-pruning errors (e.g. transient upstream failures) must keep
    using the existing retry loop — the short-circuit is scoped to the
    one specific recoverable-only-via-different-node case."""
    transient_body = (
        b'{"jsonrpc":"2.0","id":1,'
        b'"error":{"code":-32001,"message":"upstream timed out"}}'
    )
    success_body = b'{"jsonrpc":"2.0","id":1,"result":[]}'
    session = _session_returning([transient_body, success_body])
    with patch.object(eth_client_utils, "get_eth_client_session",
                      return_value=session):
        result = await send_rpc_request_to_eth_client(
            [NODE_URL], "eth_getLogs", params=[{}],
        )
    assert result == {"jsonrpc": "2.0", "id": 1, "result": []}
    assert session.post.call_count == 2, (
        "non-missing-block-data errors must still retry"
    )


@pytest.mark.asyncio
async def test_short_circuit_is_scoped_to_eth_getLogs(no_sleep):
    """A "missing block data" reply for a different method shouldn't
    be assumed equivalent — the message could mean something different
    for, say, eth_getBalance against an archive-needed query. Other
    methods continue through the existing retry decision."""
    error_body = (
        b'{"jsonrpc":"2.0","id":1,'
        b'"error":{"code":-32001,"message":"missing block data"}}'
    )
    # Code -32001 is not in the "expected" allowlist, so the helper
    # retries on it. Queue one error then one success so the retry
    # decision sees both responses: 1 call ⇒ short-circuit (regression),
    # 2 calls ⇒ retry behaved as before this change.
    success_body = b'{"jsonrpc":"2.0","id":1,"result":"0x0"}'
    session = _session_returning([error_body, success_body])
    with patch.object(eth_client_utils, "get_eth_client_session",
                      return_value=session):
        result = await send_rpc_request_to_eth_client(
            [NODE_URL], "eth_getBalance", params=["0x0", "latest"],
        )
    assert session.post.call_count == 2, (
        "non-eth_getLogs methods must not inherit the short-circuit"
    )
    assert result == {"jsonrpc": "2.0", "id": 1, "result": "0x0"}
