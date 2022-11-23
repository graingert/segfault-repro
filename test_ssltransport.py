from __future__ import annotations

import logging
import os
import socket
import ssl
import sys
import threading
import typing
import warnings


from urllib3.exceptions import HTTPWarning
from urllib3.util import ALPN_PROTOCOLS
from urllib3.util.ssltransport import SSLTransport

if typing.TYPE_CHECKING:
    from typing_extensions import ParamSpec
    from typing_extensions import Literal

    P = ParamSpec("P")



log = logging.getLogger(__name__)

CERTS_PATH = os.path.join(os.path.dirname(__file__), "certs")
DEFAULT_CERTS: dict[str, typing.Any] = {
    "certfile": os.path.join(CERTS_PATH, "server.crt"),
    "keyfile": os.path.join(CERTS_PATH, "server.key"),
    "cert_reqs": ssl.CERT_OPTIONAL,
    "ca_certs": os.path.join(CERTS_PATH, "cacert.pem"),
    "alpn_protocols": ALPN_PROTOCOLS,
}
DEFAULT_CA = os.path.join(CERTS_PATH, "cacert.pem")
DEFAULT_CA_KEY = os.path.join(CERTS_PATH, "cacert.key")


class SocketServerThread(threading.Thread):
    """
    :param socket_handler: Callable which receives a socket argument for one
        request.
    :param ready_event: Event which gets set when the socket handler is
        ready to receive requests.
    """

    USE_IPV6 = False

    def __init__(
        self,
        socket_handler: typing.Callable[[socket.socket], None],
        host: str = "localhost",
        ready_event: threading.Event | None = None,
    ) -> None:
        super().__init__()
        self.daemon = True

        self.socket_handler = socket_handler
        self.host = host
        self.ready_event = ready_event

    def _start_server(self) -> None:
        if self.USE_IPV6:
            sock = socket.socket(socket.AF_INET6)
        else:
            sock = socket.socket(socket.AF_INET)
        if sys.platform != "win32":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, 0))
        self.port = sock.getsockname()[1]

        # Once listen() returns, the server socket is ready
        sock.listen(1)

        if self.ready_event:
            self.ready_event.set()

        self.socket_handler(sock)
        sock.close()

    def run(self) -> None:
        self._start_server()


def get_unreachable_address() -> tuple[str, int]:
    # reserved as per rfc2606
    return ("something.invalid", 54321)


# consume_socket can iterate forever, we add timeouts to prevent halting.
PER_TEST_TIMEOUT = 60


def server_client_ssl_contexts() -> tuple[ssl.SSLContext, ssl.SSLContext]:
    if hasattr(ssl, "PROTOCOL_TLS_SERVER"):
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(DEFAULT_CERTS["certfile"], DEFAULT_CERTS["keyfile"])

    if hasattr(ssl, "PROTOCOL_TLS_CLIENT"):
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    client_context.load_verify_locations(DEFAULT_CA)
    return server_context, client_context


@typing.overload
def sample_request(binary: Literal[True] = ...) -> bytes:
    ...


@typing.overload
def sample_request(binary: Literal[False]) -> str:
    ...


def sample_request(binary: bool = True) -> bytes | str:
    request = (
        b"GET http://www.testing.com/ HTTP/1.1\r\n"
        b"Host: www.testing.com\r\n"
        b"User-Agent: awesome-test\r\n"
        b"\r\n"
    )
    return request if binary else request.decode("utf-8")


def validate_request(
    provided_request: bytearray, binary: Literal[False, True] = True
) -> None:
    assert provided_request is not None
    expected_request = sample_request(binary)
    assert provided_request == expected_request


@typing.overload
def sample_response(binary: Literal[True] = ...) -> bytes:
    ...


@typing.overload
def sample_response(binary: Literal[False]) -> str:
    ...


@typing.overload
def sample_response(binary: bool = ...) -> bytes | str:
    ...


def sample_response(binary: bool = True) -> bytes | str:
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    return response if binary else response.decode("utf-8")


def validate_response(
    provided_response: bytes | bytearray | str, binary: bool = True
) -> None:
    assert provided_response is not None
    expected_response = sample_response(binary)
    assert provided_response == expected_response


def validate_peercert(ssl_socket: SSLTransport) -> None:

    binary_cert = ssl_socket.getpeercert(binary_form=True)
    assert type(binary_cert) == bytes
    assert len(binary_cert) > 0

    cert = ssl_socket.getpeercert()
    assert type(cert) == dict
    assert "serialNumber" in cert
    assert cert["serialNumber"] != ""


def consume_socket(
    sock: SSLTransport | socket.socket, chunks: int = 65536
) -> bytearray:
    consumed = bytearray()
    while True:
        b = sock.recv(chunks)
        assert isinstance(b, bytes)
        consumed += b
        if b.endswith(b"\r\n\r\n"):
            break
    return consumed


class SingleTLSLayerTestCase:
    """
    Uses the SocketDummyServer to validate a single TLS layer can be
    established through the SSLTransport.
    """
    """
    A simple socket-based server is created for this class that is good for
    exactly one request.
    """

    scheme = "http"
    host = "localhost"

    server_thread: typing.ClassVar[SocketServerThread]
    port: typing.ClassVar[int]

    tmpdir: typing.ClassVar[str]
    ca_path: typing.ClassVar[str]
    cert_combined_path: typing.ClassVar[str]
    cert_path: typing.ClassVar[str]
    key_path: typing.ClassVar[str]
    password_key_path: typing.ClassVar[str]

    server_context: typing.ClassVar[ssl.SSLContext]
    client_context: typing.ClassVar[ssl.SSLContext]

    proxy_server: typing.ClassVar[SocketDummyServerTestCase]

    @classmethod
    def _start_server(
        cls, socket_handler: typing.Callable[[socket.socket], None]
    ) -> None:
        ready_event = threading.Event()
        cls.server_thread = SocketServerThread(
            socket_handler=socket_handler, ready_event=ready_event, host=cls.host
        )
        cls.server_thread.start()
        ready_event.wait(5)
        if not ready_event.is_set():
            raise Exception("most likely failed to start server")
        cls.port = cls.server_thread.port

    @classmethod
    def teardown_class(cls) -> None:
        if hasattr(cls, "server_thread"):
            cls.server_thread.join(0.1)

    @classmethod
    def setup_class(cls) -> None:
        cls.server_context, cls.client_context = server_client_ssl_contexts()

    def start_dummy_server(
        self, handler: typing.Callable[[socket.socket], None] | None = None
    ) -> None:
        def socket_handler(listener: socket.socket) -> None:
            sock = listener.accept()[0]
            try:
                with self.server_context.wrap_socket(sock, server_side=True) as ssock:
                    request = consume_socket(ssock)
                    validate_request(request)
                    ssock.send(sample_response())
            except (ConnectionAbortedError, ConnectionResetError):
                return

        chosen_handler = handler if handler else socket_handler
        self._start_server(chosen_handler)

    def test_unwrap_existing_socket(self) -> None:
        """
        Validates we can break up the TLS layer
        A full request/response is sent over TLS, and later over plain text.
        """

        def shutdown_handler(listener: socket.socket) -> None:
            sock = listener.accept()[0]
            ssl_sock = self.server_context.wrap_socket(sock, server_side=True)

            request = consume_socket(ssl_sock)
            validate_request(request)
            ssl_sock.sendall(sample_response())

            unwrapped_sock = ssl_sock.unwrap()

            request = consume_socket(unwrapped_sock)
            validate_request(request)
            unwrapped_sock.sendall(sample_response())

        self.start_dummy_server(shutdown_handler)
        sock = socket.create_connection((self.host, self.port))
        ssock = SSLTransport(sock, self.client_context, server_hostname="localhost")

        # request/response over TLS.
        ssock.sendall(sample_request())
        response = consume_socket(ssock)
        validate_response(response)

        # request/response over plaintext after unwrap.
        ssock.unwrap()
        sock.sendall(sample_request())
        response = consume_socket(sock)
        validate_response(response)

import sys
import traceback
import warnings
from types import TracebackType
from typing import Any
from typing import Callable
from typing import Generator
from typing import Optional
from typing import Type

import contextlib



# Copied from cpython/Lib/test/support/__init__.py, with modifications.
class catch_unraisable_exception:
    """Context manager catching unraisable exception using sys.unraisablehook.

    Storing the exception value (cm.unraisable.exc_value) creates a reference
    cycle. The reference cycle is broken explicitly when the context manager
    exits.

    Storing the object (cm.unraisable.object) can resurrect it if it is set to
    an object which is being finalized. Exiting the context manager clears the
    stored object.

    Usage:
        with catch_unraisable_exception() as cm:
            # code creating an "unraisable exception"
            ...
            # check the unraisable exception: use cm.unraisable
            ...
        # cm.unraisable attribute no longer exists at this point
        # (to break a reference cycle)
    """

    def __init__(self) -> None:
        self.unraisable: Optional["sys.UnraisableHookArgs"] = None
        self._old_hook: Optional[Callable[["sys.UnraisableHookArgs"], Any]] = None

    def _hook(self, unraisable: "sys.UnraisableHookArgs") -> None:
        # Storing unraisable.object can resurrect an object which is being
        # finalized. Storing unraisable.exc_value creates a reference cycle.
        self.unraisable = unraisable

    def __enter__(self) -> "catch_unraisable_exception":
        self._old_hook = sys.unraisablehook
        sys.unraisablehook = self._hook
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        assert self._old_hook is not None
        sys.unraisablehook = self._old_hook
        self._old_hook = None
        del self.unraisable


@contextlib.contextmanager
def unraisable_exception_runtest_hook() -> Generator[None, None, None]:
    with catch_unraisable_exception() as cm:
        yield
        if cm.unraisable:
            if cm.unraisable.err_msg is not None:
                err_msg = cm.unraisable.err_msg
            else:
                err_msg = "Exception ignored in"
            msg = f"{err_msg}: {cm.unraisable.object!r}\n\n"
            msg += "".join(
                traceback.format_exception(
                    cm.unraisable.exc_type,
                    cm.unraisable.exc_value,
                    cm.unraisable.exc_traceback,
                )
            )
            warnings.warn(msg)

def main():
    with unraisable_exception_runtest_hook():
        t = SingleTLSLayerTestCase()
        t.setup_class()
        t.test_unwrap_existing_socket()
        t.teardown_class()


if __name__ == "__main__":
    sys.exit(main())
