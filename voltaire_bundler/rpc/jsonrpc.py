import json
from typing import Any

# based on https://github.com/dasmith/stanford-corenlp-python/blob/master/jsonrpc.py

# JSON-RPC 2.0 error-codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_METHOD_PARAMS = -32602  # invalid number/type of parameters

# human-readable messages
ERROR_MESSAGE = {
    PARSE_ERROR: "Parse error.",
    INVALID_REQUEST: "Invalid Request.",
    METHOD_NOT_FOUND: "Method not found.",
    INVALID_METHOD_PARAMS: "Invalid parameters.",
}


class RPCFault(BaseException):
    def __init__(self, error_code, error_message, error_data=None):
        self.error_code = error_code
        self.error_message = error_message
        self.error_data = error_data

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return (
            f"<RPCFault {self.error_code}:{repr(self.error_message)} " +
            f"{repr(self.error_data)}>"
        )


class RPCParseError(RPCFault):
    """Broken rpc-package. (PARSE_ERROR)"""

    def __init__(self, error_data=None):
        RPCFault.__init__(
            self, PARSE_ERROR, ERROR_MESSAGE[PARSE_ERROR], error_data)


class RPCInvalidRPC(RPCFault):
    """Invalid rpc-package. (INVALID_REQUEST)"""

    def __init__(self, error_data=None):
        RPCFault.__init__(
            self, INVALID_REQUEST, ERROR_MESSAGE[INVALID_REQUEST], error_data)


class RPCMethodNotFound(RPCFault):
    """Method not found. (METHOD_NOT_FOUND)"""

    def __init__(self, error_data=None):
        RPCFault.__init__(
            self, METHOD_NOT_FOUND, ERROR_MESSAGE[METHOD_NOT_FOUND], error_data)


class RPCInvalidMethodParams(RPCFault):
    """Invalid method-parameters. (INVALID_METHOD_PARAMS)"""

    def __init__(self, error_data=None):
        RPCFault.__init__(
            self,
            INVALID_METHOD_PARAMS, ERROR_MESSAGE[INVALID_METHOD_PARAMS],
            error_data
        )


def dictkeyclean(d):
    """Convert all keys of the dict 'd' to (ascii-)strings.

    :Raises: UnicodeEncodeError
    """
    new_d = {}
    for (k, v) in d.iteritems():
        new_d[str(k)] = v
    return new_d


def validate_and_load_json_rpc_request(
    string: str, methods: dict[str, Any]
) -> tuple[str, dict | None, str | None]:
    try:
        data = json.loads(string)
    except ValueError as err:
        raise RPCParseError("No valid JSON. (%s)" % str(err))
    if not isinstance(data, dict):
        raise RPCInvalidRPC("No valid RPC-package.")
    if "jsonrpc" not in data:
        raise RPCInvalidRPC("Invalid Response, 'jsonrpc' missing.")
    if not isinstance(data["jsonrpc"], (str)):
        raise RPCInvalidRPC("Invalid Response, 'jsonrpc' must be a string.")
    if data["jsonrpc"] != "2.0":
        raise RPCInvalidRPC("Invalid jsonrpc version.")
    if "method" not in data:
        raise RPCInvalidRPC("Invalid Request, 'method' is missing.")
    if not isinstance(data["method"], (str)):
        raise RPCInvalidRPC("Invalid Request, 'method' must be a string.")
    if data["method"] not in methods:
        raise RPCMethodNotFound("RPC method not found.")
    if "params" not in data:
        data["params"] = ()
    # convert params-keys from unicode to str
    elif isinstance(data["params"], dict):
        try:
            data["params"] = dictkeyclean(data["params"])
        except UnicodeEncodeError:
            raise RPCInvalidMethodParams("Parameter-names must be in ascii.")
    elif not isinstance(data["params"], (list, tuple)):
        raise RPCInvalidRPC(
                "Invalid Request, 'params' must be an array or object.")
    if not (
        len(data) == 3 or
        ("id" in data and len(data) == 4)
    ):
        raise RPCInvalidRPC("Invalid Request, additional fields found.")

    # notification / request
    if "id" not in data:
        return data["method"], data["params"], None  # notification(no id)
    else:
        return data["method"], data["params"], data["id"]  # request
