"""
This module is a simple event bus implementation for message based interprocess
communiction.
It is uses unix IPC sockets to send messages between python threads,
also between python threads and the Rust p2p thread.
Note: Voltaire p2p implementation is written in rust, as the python libp2p
implementation is not maintained.
The main architecture consist of Endpoints(server) and Clients.
Each Endpoint can receive requests from Clients.
Each Endpoint has its own IPC file which it listens to for messages
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

RequestEvent = Dict[str, Any]
ResponseEvent = Dict[str, Any]
ResponseFunction = Callable[[Any], Awaitable[ResponseEvent]]
PartialResponseFunction = partial[Awaitable[ResponseEvent]]
DEFAULT_LIMIT = 2 ** 16

async def _start_pipe_server(client_connected_cb, *, path,
                            loop=None, limit=DEFAULT_LIMIT):
    """Start listening for connection using Win32 named pipes."""

    loop = loop or asyncio.get_event_loop()

    def factory():
        reader = asyncio.StreamReader(limit=limit, loop=loop)
        protocol = asyncio.StreamReaderProtocol(
            reader, client_connected_cb, loop=loop
        )
        return protocol

    # NOTE: has no "wait_closed()" coroutine method.
    server, *_ = await loop.start_serving_pipe(factory, address=path)
    return server


async def _open_pipe_connection(path: Any, *, loop=None,
                               limit=DEFAULT_LIMIT, **kwds):
    """Connect to a server using a Win32 named pipe."""

    loop = loop or asyncio.get_event_loop()

    reader = asyncio.StreamReader(limit=limit, loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
    transport, _ = await loop.create_pipe_connection(
        lambda: protocol, path, **kwds
    )
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    return reader, writer

# Alias UNIX socket / Win32 named pipe functions to platform-agnostic names.
if sys.platform == 'win32':
    open_ipc_connection = _open_pipe_connection
else:
    open_ipc_connection = asyncio.open_unix_connection

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

    async def _serve_until(self, cancel, filepath: str, ready=None):
        """IPC server."""
        server = await asyncio.wait_for(
            _start_pipe_server(self._handle_request_cb, path=filepath),
            timeout=5.0
        )
        try:
            ready.set_result(None)
            await cancel
        finally:
            server.close()
            if hasattr(server, 'wait_closed'):
                await server.wait_closed()
            else:
                server.close()

    async def _start_server(self, filepath: str):
        server = await asyncio.start_unix_server(
                self._handle_request_cb, filepath)
        async with server:
            await server.serve_forever()

    async def _start_server_win32(self, filepath: str):
        loop = asyncio.get_event_loop()
        cancel = asyncio.Future()
        path = rf'\\.\pipe\{filepath.replace('.ipc', '')}'
        ready = asyncio.Future()
        server = loop.create_task(self._serve_until(
            cancel=cancel, filepath=path, ready=ready
        ))
        try:
            await ready
            await cancel
        finally:
            await server

    async def start_server(self, filepath: str) -> None:
        """
        Starts the Endpoint server to listen to requests on an IPC socket
        It creates the .ipc file if it doesn't exist
        """
        logging.info("Starting " + self.id)
        if sys.platform == 'win32':
            await self._start_server_win32(filepath)
        else:
            await self._start_server(filepath)

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
        This callback function is passed to start_unix_server and is called whenever
        a new client connection is established.
        This function waits for a RequestEvent from a client, routes the RequestEvent to
        its target response_function and then broadcast the ResponseEvent back to the
        Client.
        """
        try:
            request_event: RequestEvent = await _listen(reader)
            # response_event: ResponseEvent = await self._get_response(
            #     request_event
            # )
            index = self.event_names.index(request_event["request_type"])
            response_function = self.response_functions_list[index]
            response_event = await response_function(
                    request_event["request_arguments"])
            if "p2p_received" not in request_event["request_type"]:
                await _broadcast(response_event, writer)
        finally:
            writer.close()
            # waits for the stream to close in case of unexpected interruption
            await writer.wait_closed()

    async def _get_response(
            self, request_event: RequestEvent) -> ResponseEvent:
        index = self.event_names.index(request_event["request_type"])
        response_function = self.response_functions_list[index]
        return await response_function(request_event["request_arguments"])


class Client:
    """
    This Class represent a client that can send RequestEvent to an
    Endpoint(server) and receives a ResponseEvent
    """

    server_id: str

    def __init__(self, id: str) -> None:
        self.server_id = id

    async def request(self, request_event: RequestEvent) -> ResponseEvent:
        """
        This function establish a Unix socket connection to an Endpoint
        and sends a RequestEvents and waits for a ResponseEvent.
        """
        if sys.platform == 'win32':
            path = rf'\\.\pipe\{self.server_id}'
        else:
            path = self.server_id + ".ipc"
        reader, writer = await open_ipc_connection(path)

        await _broadcast(request_event, writer)
        response_event: ResponseEvent = await _listen(reader)

        return response_event

    async def broadcast_only(self, request_event: RequestEvent) -> None:
        """
        This function establish a Unix socket connection to an Endpoint and
        sends a RequestEvents and waits for a ResponseEvent.
        """
        if sys.platform == 'win32':
            path = r'\\.\pipe\p2p_endpoint'
        else:
            path = "p2p_endpoint.ipc"

        try:
            _, writer = await open_ipc_connection(path)
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
