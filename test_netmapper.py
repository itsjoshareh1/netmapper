import socket

import pytest

from netmapper import check_port, parse_arp, parse_network, scan_host, worst_risk


def test_private_network_ok():
    assert parse_network("192.168.1.0/24").num_addresses == 256


def test_public_network_rejected():
    with pytest.raises(ValueError):
        parse_network("8.8.8.0/24")


def test_huge_network_rejected():
    with pytest.raises(ValueError):
        parse_network("10.0.0.0/8")


def test_parse_arp_macos_line():
    out = "router.lan (192.168.1.1) at a4:83:e7:1:2:3 on en0 ifscope [ethernet]"
    assert parse_arp(out) == {"192.168.1.1": "a4:83:e7:01:02:03"}


def test_worst_risk():
    assert worst_risk([]) == "none"
    assert worst_risk([80, 23]) == "high"
    assert worst_risk([443]) == "low"


def test_scan_finds_open_port():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        assert check_port("127.0.0.1", port) == "open"
        result = scan_host("127.0.0.1", ports=[port])
        assert result["alive"] and result["open_ports"] == [port]
    finally:
        server.close()

# TODO: add a test for MAC vendor lookup once you build it.
