import socket
from collections.abc import Iterator
from typing import Any

import pytest

_LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost"}


@pytest.fixture(autouse=True)
def _block_network(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
) -> Iterator[None]:
    """Unit tests must never reach the network (CLAUDE.md rule 8).

    Loopback stays allowed because asyncio on Windows builds its self-pipe with a
    local socket connection. Tests marked ``live`` are exempt.
    """
    if request.node.get_closest_marker("live"):
        yield
        return

    real_connect = socket.socket.connect

    def guarded_connect(self: socket.socket, address: Any) -> None:
        host = address[0] if isinstance(address, tuple) else address
        if host not in _LOCAL_HOSTS:
            raise RuntimeError(f"Network access blocked in tests: {address!r}")
        real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    yield
