import asyncio
from dataclasses import field
import pickle
from typing import Callable
import inspect
from functools import partial
import logging

from .events import RequestEvent, ResponseEvent

# credits :https://github.com/ethereum/trinity/issues/507


async def _listen(reader: asyncio.StreamReader) -> ResponseEvent:
    raw_size = await reader.readexactly(4)
    size = int.from_bytes(raw_size, "little")
    message = await reader.readexactly(size)
    result: ResponseEvent = pickle.loads(message)

    return result


async def _broadcast(
    requestEvent: RequestEvent, writer: asyncio.StreamWriter
) -> None:
    message = pickle.dumps(requestEvent)
    size = len(message)
    writer.write(size.to_bytes(4, "little"))
    writer.write(message)
    await writer.drain()


class Endpoint:
    event_names: list = field(default_factory=list[str])
    response_functions_list: list = field(default_factory=list[Callable])

    def __init__(self, id: str) -> None:
        self.id = id
        self.event_names = []
        self.response_functions_list = []

    async def start_server(self) -> None:
        logging.info("Starting " + self.id)
        filepath = self.id + ".ipc"
        server = await asyncio.start_unix_server(
            self._handle_request, filepath
        )
        async with server:
            await server.serve_forever()

    def add_event_and_response_function(
        self, event_name: str, response_function: Callable
    ):
        if event_name not in self.event_names:
            self.event_names.append(event_name)
            self.response_functions_list.append(response_function)
        else:
            raise ValueError("Event name is not unique")

    def add_events_and_response_functions_by_prefix(
        self, prefix: str, decorator_func=None
    ) -> None:
        method_list = inspect.getmembers(self, predicate=inspect.ismethod)

        for method in method_list:
            method_name = method[0]
            method_obj = method[1]
            if method_name.startswith(prefix):
                prefix_len = len(prefix)
                event_name = method_name[prefix_len:]  # remove prefix

                if decorator_func is not None:
                    response_function = partial(decorator_func, method_obj)
                else:
                    response_function = method_obj

                self.add_event_and_response_function(
                    event_name, response_function
                )

    async def _handle_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                request_event: RequestEvent = await _listen(reader)
                response_event: ResponseEvent = await self._get_response(
                    request_event
                )
                await _broadcast(response_event, writer)
        finally:
            writer.close()
            await writer.wait_closed()

    async def _get_response(
        self, request_event: RequestEvent
    ) -> ResponseEvent:
        index = self.event_names.index(request_event.request_type)
        response_function: Callable = self.response_functions_list[index]
        return await response_function(request_event)


class Client:
    server_id: str

    def __init__(self, id: str) -> None:
        self.server_id = id

    async def request(self, request_event: RequestEvent) -> ResponseEvent:
        filepath = self.server_id + ".ipc"
        reader, writer = await asyncio.open_unix_connection(filepath)

        await _broadcast(request_event, writer)
        response_event: ResponseEvent = await _listen(reader)

        return response_event
