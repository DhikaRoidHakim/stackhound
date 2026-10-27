import socket

import pytest


def test_external_connect_is_blocked() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s,
        pytest.raises(RuntimeError, match="Network access blocked"),
    ):
        s.connect(("192.0.2.1", 80))  # TEST-NET-1, never routable
