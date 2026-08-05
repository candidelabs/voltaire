"""
This module is a simple event bus implementation for message based interprocess
communication.
On non-Windows systems, it uses Unix IPC sockets to send messages between
python threads, and also between python threads and the Rust p2p thread.
On Windows, it uses TCP on localhost with .port files for service discovery.
Note: Voltaire p2p implementation is written in rust, as the python libp2p
implementation is not maintained.
The main architecture consist of Endpoints(server) and Clients.
Each Endpoint can receive requests from Clients.
Each Endpoint has its own IPC/port file which it listens to for messages
from clients.

based on :https://github.com/ethereum/trinity/issues/507
"""

import asyncio
import inspect
import logging
import pickle
import sys
from dataclasses import field
from functools import partial
from typing import Any, Awaitable, Callable, Dict, Optional

IS_WINDOWS = sys.platform == "win32"

# Upper bound on how long a Client.request() may wait for a matching response.
# Sized well above the slowest realistic handler (gas estimation, which chains
# multiple upstream eth_calls) so the timeout only fires when a response was
# truly dropped — e.g. a handler exception path or a "p2p_received" request
# that legitimately never replies. Without this bound, a missing reply would
# hang the caller indefinitely.
_REQUEST_TIMEOUT_S = 120.0

RequestEvent = Dict[str, Any]
ResponseEvent = Dict[str, Any]
ResponseFunction = Callable[[Any], Awaitable[ResponseEvent]]
PartialResponseFunction = partial[Awaitable[ResponseEvent]]


class Endpoint:
    """This is a class representation of an Endpoint that can receive request
    from clients.
    each event name in the event_names list correspond to an function object in
    the response_functions_list that can process a RequestEvent and return
    a ResponseEvent.

    :param event_names: A list of event names
    :type event_names: list[str]
    :param response_functions_list: A list of function objects that can process
    requests
    :type response-function_list:List[PartialResponseFunction|ResponseFunction]
    """

    event_names: list[str] = field(default_factory=list[str])
    response_functions_list: list[PartialResponseFunction | ResponseFunction] = field(
        default_factory=list
    )

    def __init__(self, id: str) -> None:
        self.id = id
        self.event_names = []
        self.response_functions_list = []

    async def start_server(self, filepath: str) -> None:
        """
        Starts the Enpoint server to listen to requests on an IPC socket.
        On non-Windows, uses Unix domain sockets (.ipc files).
        On Windows, uses TCP on localhost with a .port file for discovery.
        """
        logging.info("Starting " + self.id)
        # Backlog default in asyncio is 100; bump it so the kernel doesn't RST
        # bursts of incoming IPC connections under high RPC concurrency. With
        # the multiplexed Client a single connection is reused, so in normal
        # operation only a handful of connects are needed — this is purely
        # headroom for reconnects/legacy callers.
        if IS_WINDOWS:
            server = await asyncio.start_server(
                    self._handle_request_cb, '127.0.0.1', 0, backlog=4096)
            port = server.sockets[0].getsockname()[1]
            port_filepath = filepath.replace('.ipc', '.port')
            with open(port_filepath, 'w') as f:
                f.write(str(port))
            logging.info(
                f"Started {self.id} on 127.0.0.1:{port}")
        else:
            server = await asyncio.start_unix_server(
                    self._handle_request_cb, filepath, backlog=4096)
        async with server:
            await server.serve_forever()

    def add_event_and_response_function(
        self,
        event_name: str,
        response_function: PartialResponseFunction | ResponseFunction,
    ) -> None:
        """
        Adds an event name and it's function object.
        """
        if event_name not in self.event_names:
            self.event_names.append(event_name)
            self.response_functions_list.append(response_function)
        else:
            raise ValueError("Event name is not unique")

    def add_events_and_response_functions_by_prefix(
        self,
        prefix: str,
        decorator_func: Optional[Callable[[Any], Awaitable[ResponseEvent]]] = None,
    ) -> None:
        """
        When a class inherets the Enpoint class, this functions can add all
        functions in the class that has a specific prefix to the event_names
        and the reponse_functions_list based on the function name.
        This way a function only needs to include a certain prefix in it's
        name to be included automatically.
        """
        method_list: list[tuple[str, ResponseFunction]] = inspect.getmembers(
            self, predicate=inspect.ismethod
        )

        for method in method_list:
            method_name = method[0]
            method_obj = method[1]
            if method_name.startswith(prefix):
                prefix_len = len(prefix)
                event_name = method_name[prefix_len:]  # remove prefix
                response_function: PartialResponseFunction | ResponseFunction
                if decorator_func is not None:
                    response_function = partial(decorator_func, method_obj)
                else:
                    response_function = method_obj

                self.add_event_and_response_function(
                        event_name, response_function)

    async def _handle_request_cb(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Connection callback for start_unix_server / start_server.

        Reads framed envelopes ``{"id": int, "payload": RequestEvent}`` in a
        loop from a single connection, dispatching each one to its own task so
        that a slow request (e.g. ``eth_estimateUserOperationGas``) does not
        block other in-flight requests sharing the same client connection.

        Writes back ``{"id": int, "payload": ResponseEvent}``; writes are
        serialized through a per-connection lock so concurrent dispatched
        tasks don't interleave bytes on the wire.
        """
        write_lock = asyncio.Lock()
        pending: set[asyncio.Task[None]] = set()
        try:
            while True:
                try:
                    envelope: Dict[str, Any] = await _listen(reader)
                except (asyncio.IncompleteReadError, OSError):
                    break
                task = asyncio.create_task(
                    self._dispatch(envelope, writer, write_lock)
                )
                pending.add(task)
                task.add_done_callback(pending.discard)
        finally:
            # Let in-flight dispatches finish writing before closing the socket
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _dispatch(
        self,
        envelope: Dict[str, Any],
        writer: asyncio.StreamWriter,
        write_lock: asyncio.Lock,
    ) -> None:
        req_id = envelope.get("id")
        request_event: RequestEvent = envelope["payload"]
        try:
            index = self.event_names.index(request_event["request_type"])
            response_function = self.response_functions_list[index]
            response_event = await response_function(
                request_event["request_arguments"]
            )
        except Exception:
            # Handlers are wrapped in exception_handler_decorator, so this is
            # unexpected; log and drop the response — the client's future will
            # surface as a hang only if a malformed request bypassed the
            # decorator (no current callers do).
            logging.exception(
                "unhandled error dispatching IPC request id=%s", req_id
            )
            return

        if "p2p_received" in request_event["request_type"]:
            return

        try:
            async with write_lock:
                await _broadcast(
                    {"id": req_id, "payload": response_event}, writer
                )
        except OSError:
            # Client went away; the connection's read loop will exit on its
            # next _listen and clean up.
            pass


class Client:
    """
    Client that sends a RequestEvent to an Endpoint and awaits the matching
    ResponseEvent.

    Requests are multiplexed over a single persistent connection per Client
    instance. Each request is tagged with a monotonically-increasing id; a
    background reader task routes incoming responses back to the originating
    caller's future by id. This avoids opening a fresh Unix-socket connection
    per RPC call, which previously caused the kernel listen-backlog to
    overflow under high concurrency (manifesting as
    ``ConnectionResetError: Connection lost`` on ``writer.drain()``).
    """

    server_id: str

    def __init__(self, id: str) -> None:
        self.server_id = id
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._reader_task: Optional[asyncio.Task[None]] = None
        # asyncio.Lock() is loop-agnostic since Python 3.10, so we can
        # create these eagerly; doing so closes a race where two concurrent
        # first callers each created their own lock and both connected.
        self._connect_lock: asyncio.Lock = asyncio.Lock()
        self._write_lock: asyncio.Lock = asyncio.Lock()
        self._pending: Dict[int, asyncio.Future[Any]] = {}
        self._next_id: int = 0

    async def _ensure_connected(self) -> None:
        async with self._connect_lock:
            if self._writer is not None and not self._writer.is_closing():
                return
            # A previous connection's reader task may still be alive (e.g.
            # request() tore down after a write error while the reader was
            # blocked on the dead stream). Cancel it so it can't run its own
            # teardown against the connection we're about to create.
            if self._reader_task is not None:
                self._reader_task.cancel()
                self._reader_task = None
            if IS_WINDOWS:
                port_filepath = self.server_id + ".port"
                with open(port_filepath, 'r') as f:
                    port = int(f.read().strip())
                reader, writer = await asyncio.open_connection(
                        '127.0.0.1', port)
            else:
                filepath = self.server_id + ".ipc"
                reader, writer = await asyncio.open_unix_connection(
                        filepath)
            self._reader, self._writer = reader, writer
            self._reader_task = asyncio.create_task(self._read_loop(reader))

    async def _read_loop(self, reader: asyncio.StreamReader) -> None:
        # The stream is passed in (rather than read from self._reader) so a
        # task that outlives its connection keeps reading its own dead stream
        # instead of stealing frames from a reconnected one.
        try:
            while True:
                envelope = await _listen(reader)
                req_id = envelope.get("id")
                fut = self._pending.pop(req_id, None)
                if fut is not None and not fut.done():
                    fut.set_result(envelope["payload"])
        except (asyncio.IncompleteReadError, OSError) as exc:
            # Only tear down if we're still the active connection; a stale
            # task waking up after a reconnect must not close the new one.
            if self._reader is reader:
                self._teardown(exc)
        except Exception as exc:
            logging.exception("IPC client read loop crashed for %s", self.server_id)
            if self._reader is reader:
                self._teardown(exc)

    def _teardown(self, exc: BaseException) -> None:
        task = self._reader_task
        self._reader_task = None
        # Don't cancel ourselves when teardown runs inside the reader task's
        # own exception handler — it's about to exit anyway.
        if task is not None and task is not asyncio.current_task():
            task.cancel()
        if self._writer is not None:
            try:
                self._writer.close()
            except Exception:
                pass
        self._writer = None
        self._reader = None
        for fut in self._pending.values():
            if not fut.done():
                fut.set_exception(exc)
        self._pending.clear()

    async def request(self, request_event: RequestEvent) -> ResponseEvent:
        """
        Send a RequestEvent over the persistent connection and await the
        matching response. Reconnects transparently if the connection has
        been torn down by a previous error.
        """
        # One quick reconnect attempt if the persistent connection dropped
        # between requests.
        for attempt in range(2):
            await self._ensure_connected()
            assert self._writer is not None and self._write_lock is not None
            req_id = self._next_id
            self._next_id += 1
            fut: asyncio.Future[Any] = asyncio.get_running_loop().create_future()
            self._pending[req_id] = fut
            envelope = {"id": req_id, "payload": request_event}
            try:
                async with self._write_lock:
                    await _broadcast(envelope, self._writer)
            except OSError as exc:
                self._pending.pop(req_id, None)
                self._teardown(exc)
                if attempt == 0:
                    continue
                raise
            try:
                return await asyncio.wait_for(fut, timeout=_REQUEST_TIMEOUT_S)
            except asyncio.TimeoutError:
                # Response was dropped (handler exception path, p2p_received
                # branch, or a peer that never replied). Surface as a timeout
                # rather than hanging the caller; don't retry — the connection
                # itself is still healthy.
                self._pending.pop(req_id, None)
                raise
        # Unreachable — the loop either returns or raises.
        raise RuntimeError("unreachable")

    async def broadcast_only(self, request_event: RequestEvent) -> None:
        """
        This function establish a connection to an Endpoint and
        sends a RequestEvent without waiting for a response.
        Uses Unix sockets on non-Windows, TCP on localhost on Windows.
        """
        if IS_WINDOWS:
            port_filepath = "p2p_endpoint.port"
            try:
                with open(port_filepath, 'r') as f:
                    port = int(f.read().strip())
                _, writer = await asyncio.open_connection(
                        '127.0.0.1', port)
            except (ConnectionRefusedError, FileNotFoundError, ValueError):
                return
        else:
            filepath = "p2p_endpoint.ipc"
            try:
                _, writer = await asyncio.open_unix_connection(filepath)
            except ConnectionRefusedError:
                return

        await _broadcast(request_event, writer)


async def _listen(
    reader: asyncio.StreamReader,
) -> RequestEvent | ResponseEvent:
    """
    This function is used by both the Endpoint to listen to requests and the
    Client to listen to responses
    """
    raw_size = await reader.readexactly(4)
    size = int.from_bytes(raw_size, "little")
    message = await reader.readexactly(size)
    result: RequestEvent = pickle.loads(message)

    return result


async def _broadcast(
    event: RequestEvent | ResponseEvent, writer: asyncio.StreamWriter
) -> None:
    """
    This function is used by both the Endpoint to return responses and
    the Client to send requests
    """
    message = pickle.dumps(event)
    size = len(message)
    writer.write(size.to_bytes(4, "little"))
    writer.write(message)
    await writer.drain()
