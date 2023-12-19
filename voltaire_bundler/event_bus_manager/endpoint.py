"""
This module is a simple event bus implementation for message based interprocess 
communiction.
It is uses unix IPC sockets to send messages between python threads, also between python
threads and the Rust p2p thread.
Note: Voltaire p2p implementation is written in rust, as the python libp2p 
implementation is not maintained.
The main architecture consist of Endpoints(server) and Clients. Each Endpoint can 
receive requests from Clients.
Each Endpoint has its own IPC file which it listens to for messages from clients.

based on :https://github.com/ethereum/trinity/issues/507
"""

import asyncio
import pickle
import inspect
import logging
from functools import partial
from dataclasses import field
from typing import Dict, Any, Callable, Awaitable, Optional

RequestEvent = Dict[str, Any]
ResponseEvent = Dict[str, Any]
ResponseFunction = Callable[[Any], Awaitable[ResponseEvent]]
PartialResponseFunction = partial[Awaitable[ResponseEvent]]

class Endpoint:
    """This is a class representation of an Endpoint that can receive request from
    clients.
    each event name in the event_names list correspond to an function object in the
    response_functions_list that can process a RequestEvent and return a ResponseEvent.

    :param event_names: A list of event names
    :type event_names: list[str]
    :param response_functions_list: A list of function objects that can process requests
    :type response-function_list: List[PartialResponseFunction | ResponseFunction]
    """

    event_names: list[str] = field(default_factory=list[str])
    response_functions_list: list[
        PartialResponseFunction | ResponseFunction
    ] = field(default_factory=list)

    def __init__(self, id: str) -> None:
        self.id = id
        self.event_names = []
        self.response_functions_list = []

    async def start_server(self, filepath:str) -> None:
        """
        Starts the Enpoint server to listen to requests on an IPC socket
        It creates the .ipc file if it doesn't exist
        """
        logging.info("Starting " + self.id)
        # filepath = self.id + ".ipc"
        server = await asyncio.start_unix_server(
            self._handle_request_cb, filepath
        )
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
        When a class inherets the Enpoint class, this functions can add all functions
        in the class that has a specific prefix to the event_names and the 
        reponse_functions_list based on the function name.
        This way a function only needs to include a certain prefix in it's name to
        be included automatically.
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
                    event_name, response_function
                )

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
            response_event =  await response_function(request_event["request_arguments"])
            if "p2p_received" not in request_event["request_type"]:
                await _broadcast(response_event, writer)
        finally:
            writer.close()
            await writer.wait_closed() # waits for the stream to close in case of unexpected interruption

    async def _get_response(
        self, request_event: RequestEvent
    ) -> ResponseEvent:
        index = self.event_names.index(request_event["request_type"])
        response_function = self.response_functions_list[index]
        return await response_function(request_event["request_arguments"])


class Client:
    """
    This Class represent a client that can send RequestEvent to an Endpoint(server) and
    receives a ResponseEvent
    """
    server_id: str

    def __init__(self, id: str) -> None:
        self.server_id = id

    async def request(self, request_event: RequestEvent) -> ResponseEvent:
        """
        This function establish a Unix socket connection to an Endpoint and sends a
        RequestEvents and waits for a ResponseEvent.
        """
        filepath = self.server_id + ".ipc"
        reader, writer = await asyncio.open_unix_connection(filepath)

        await _broadcast(request_event, writer)
        response_event: ResponseEvent = await _listen(reader)

        return response_event
    
    async def broadcast_only(self, request_event: RequestEvent) -> None:
        """
        This function establish a Unix socket connection to an Endpoint and sends a
        RequestEvents and waits for a ResponseEvent.
        """
        # filepath = self.server_id + ".ipc"
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
    This function is used by both the Endpoint to listen to requests and the Client to
    listen to responses
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
    This function is used by both the Endpoint to return responses and the Client to
    send requests
    """

    message = pickle.dumps(event)
    size = len(message)
    writer.write(size.to_bytes(4, "little"))
    writer.write(message)
    await writer.drain()
