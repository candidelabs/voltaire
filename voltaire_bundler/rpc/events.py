from voltaire_bundler.event_bus_manager.events import (
    RequestEvent,
    ResponseEvent,
)


class RPCCallResponseEvent(RequestEvent):
    def __init__(self, payload, is_error=False):
        super().__init__()
        self.payload = payload
        self.is_error = is_error


class RPCCallRequestEvent(ResponseEvent):
    def __init__(self, request_type, request_arguments):
        super().__init__()
        self.request_type = request_type
        self.req_arguments = request_arguments

    def expected_response_type():
        return RPCCallResponseEvent
