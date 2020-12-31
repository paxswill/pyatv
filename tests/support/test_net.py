"""Unit tests for the net support module."""

import typing
import binascii
import collections
import ipaddress
import platform
import pathlib
import json
import re
import socket
import subprocess
import sys
from unittest.mock import patch

import pytest
import netifaces

from pyatv.support.net import get_private_addresses, tcp_keepalive, mcast_socket
from pyatv.exceptions import NotSupportedError


skip_darwin = pytest.mark.skipif(
    platform.system() == "Darwin",
    reason="not applicable to Darwin",
)


def skip_before_win_build(build_number: int):
    """Mark a test to be skipped if Windows is earlier than the given build."""
    system = platform.system()
    version = platform.version()
    return pytest.mark.skipif(
        (
            system == "Windows"
            and tuple(map(int, version.split("."))) < (10, 0, build_number)
        ),
        reason="Windows build number too low",
    )


@pytest.fixture(autouse=False)
def mock_address():
    addresses: typing.MutableMapping[str, typing.MutableSequence[str]] = {}

    def _add(interface: str, address: ipaddress.IPv4Address):
        addresses.setdefault(interface, []).append(address)

    def _ifaddresses(interface: str):
        iface_addresses = addresses.get(interface)
        if not iface_addresses:
            return {}

        inet_addresses = [
            {"addr": str(addr), "netmask": "255.255.255.0"} for addr in iface_addresses
        ]
        return {netifaces.AF_INET: inet_addresses}

    with patch("netifaces.interfaces") as mock_interfaces:
        with patch("netifaces.ifaddresses") as mock_ifaddr:
            mock_interfaces.side_effect = lambda: list(addresses.keys())
            mock_ifaddr.side_effect = _ifaddresses
            yield _add


@pytest.fixture
def mock_server():
    sock = socket.socket()
    # 127.0.0.1 *must* be used when testing on macOS
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    yield sock
    sock.close()


@pytest.fixture
def mock_client(mock_server):
    sock = socket.socket()
    sock.connect(mock_server.getsockname())
    yield sock
    sock.close()


def test_no_address(mock_address):
    assert get_private_addresses() == []


def test_private_addresses(mock_address):
    mock_address("wlan0", "10.0.0.1")
    mock_address("eth0", "192.168.0.1")
    mock_address("eth1", "172.16.0.1")

    assert get_private_addresses() == [
        ipaddress.ip_address("10.0.0.1"),
        ipaddress.ip_address("192.168.0.1"),
        ipaddress.ip_address("172.16.0.1"),
    ]


def test_public_addresses(mock_address):
    mock_address("eth0", "1.2.3.4")
    mock_address("eth1", "8.8.8.8")
    assert get_private_addresses() == []


def test_localhost(mock_address):
    mock_address("eth0", "127.0.0.1")
    assert get_private_addresses() == [ipaddress.IPv4Address("127.0.0.1")]


# Windows 10 1709 (build 16299) is the first version with TCP_KEEPIDLE
# ref: https://github.com/python/cpython/blob/66d3b589c44fcbcf9afe1e442d9beac3bd8bcd34/Modules/socketmodule.c#L318-L322 # noqa
@skip_before_win_build(16299)
# More specifically, TCP_KEEPIDLE and TCP_KEEPINTVL were added in 3.7, while 3.6.5 added
# TCP_KEEPCNT
# ref: `socket.SO_*` documentation.
@pytest.mark.skipif(sys.version_info < (3, 7), reason="keepalive added in 3.7")
def test_keepalive(mock_server, mock_client):
    """Test that TCP keepalive can be enabled."""
    server2client, client_address = mock_server.accept()
    with server2client:
        # No assert, as we're just testing that enabling keepalive works
        tcp_keepalive(mock_client)


# TCP keepalive options to remove one at a time
TCP_KEEPALIVE_OPTIONS = [
    # Darwin has a hard-coded value for the equivalent option
    pytest.param("TCP_KEEPIDLE", marks=skip_darwin),
    "TCP_KEEPINTVL",
    "TCP_KEEPCNT",
]


@pytest.mark.parametrize("missing_option", TCP_KEEPALIVE_OPTIONS)
def test_keepalive_missing_sockopt(
    missing_option,
    mock_server,
    mock_client,
    monkeypatch,
):
    """Test that missing keepalive options raise `NotSupportedError`."""
    # If the option is already missing, don't raise an error (raising=False)
    monkeypatch.delattr(socket, missing_option, raising=False)
    server2client, client_address = mock_server.accept()
    with server2client:
        with pytest.raises(NotSupportedError):
            tcp_keepalive(mock_client)


IPAddress = typing.Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


InterfaceGroupCount = typing.Mapping[str, typing.Mapping[IPAddress, int]]


@pytest.mark.skipif(
    platform.system() == "Linux" and "microsoft" in platform.release(),
    reason="IPv4 multicast seems to broken in WSL"
)
class TestMulticastGroup:
    @pytest.fixture(autouse=True)
    def stub_netifaces(self):
        """Override the root-level netifaces stubbing."""
        pass

    # See the comment in _get_multicast_groups_linux for explanation of these regexes.
    _linux_igmp_device_regex = re.compile(r"^\d+\s+(\S+)\s*:\s*\d+\s+\S+$")
    _linux_igmp_addr_regex = re.compile(r"^\t{4}([0-9A-Fa-f]{8})\s+(\d+)(?:\s+\S+){2}$")
    _linux_igmp6_regex = re.compile(
        r"^\d+\s+(\S+)\s+([0-9A-Fa-f]{32})\s+(\d+)(?:\s+\S+){2}$"
    )

    @classmethod
    def _get_multicast_groups_linux(
        cls,
    ) -> InterfaceGroupCount:
        interface_addresses: typing.MutableMapping[
            str, typing.MutableMapping[IPAddress, int]
        ] = collections.defaultdict(dict)
        # Linux exposes IGMP groups in /proc/net/igmp. The structure of that file is a
        # bit weird. The first line is a header, but not all of the fields are on all
        # lines. The fields (at least as of Linux 5.9) are:
        # Idx, Device, Count, Querier
        # After that, the next four fields apply to group-specific entries that follow
        # each device entry. These fields are:
        # Group (aka the multicast address), Users, Timer, Reporter.
        # For IPv6, the relevant file is /proc/net/igmp6 (even though the relevant
        # protocol for IPv6 is called MLD, not IGMP). The structure of this file is a
        # bit simpler:
        # Index, Device, Group (aka address), users, ... (the rest we don't care about).
        # For our purposes, we're looking for device/interface, group/address, and the
        # number of users for that group/address.
        igmp_path = pathlib.Path("/proc/net/igmp")
        if igmp_path.exists():
            igmp_entries = igmp_path.read_text()
            current_device: typing.Optional[str] = None
            # Skip the first line as it's a header
            for line in igmp_entries.splitlines()[1:]:
                device_match = cls._linux_igmp_device_regex.match(line)
                if device_match:
                    current_device = device_match.group(1)
                else:
                    addr_match = cls._linux_igmp_addr_regex.match(line)
                    assert current_device is not None, "Unexpected igmp address line"
                    assert addr_match, "Unknown /proc/net/igmp format encountered"
                    raw_addr, count = addr_match.groups()
                    # The address count is backwards (at least on x86 and ARM. I don't
                    # have a big endian machine running Linux handy to check otherwise.
                    backwards_addr = binascii.unhexlify(raw_addr)
                    addr = ipaddress.IPv4Address(bytes(reversed(backwards_addr)))
                    count = int(count)
                    interface_addresses[current_device][addr] = count

        igmp6_path = pathlib.Path("/proc/net/igmp6")
        if igmp6_path.exists():
            igmp6_entries = igmp6_path.read_text()
            for line in igmp6_entries.splitlines():
                match = cls._linux_igmp6_regex.match(line)
                assert match, "Unknown /proc/net/igmp6 format encountered"
                device, addr, count = match.groups()
                addr = ipaddress.IPv6Address(int(addr, base=16))
                count = int(count)
                interface_addresses[device][addr] = count

        return interface_addresses

    _windows_netsh_iface_regex = re.compile(r"^Interface (\d+):.*$")
    _windows_netsh_group_regex = re.compile(
        r"^\d+\s+(\d+)\s+(?:Yes|No)\s+([A-Fa-f0-9:.]+)\s*$"
    )

    @classmethod
    def _get_multicast_groups_windows(cls) -> InterfaceGroupCount:
        # Windows provides access to multicast groups through
        # `netsh interface ipv[4,6] show joins`, but that is keyed by the interface
        # index or friendly name. We can associate interface indexes with interface
        # GUIDs with a Powershell pipeline (there are other ways, but the pipeline is
        # the simplest). We need the GUIDs as that's how netifaces identifies interfaces
        # (and of course the stdlib socket.if_nameindex() uses the interface short name,
        # which isn't used anywhere else).
        netsh_command = ["netsh.exe", "interface", "ipv4", "show", "joins"]
        netsh_ipv4_ret = subprocess.run(
            netsh_command, stdout=subprocess.PIPE, check=True, encoding="utf-8"
        )
        netsh_command[2] = "ipv6"
        netsh_ipv6_ret = subprocess.run(
            netsh_command, stdout=subprocess.PIPE, check=True, encoding="utf-8"
        )
        netsh_both = netsh_ipv4_ret.stdout + netsh_ipv6_ret.stdout
        interface_index_addresses: typing.MutableMapping[
            int, typing.MutableMapping[IPAddress, int]
        ] = collections.defaultdict(dict)
        current_interface: typing.Optional[int] = None
        # Filter out completely blank lines
        ipv4_lines = filter(None, netsh_both.splitlines())
        for line in ipv4_lines:
            iface_match = cls._windows_netsh_iface_regex.match(line)
            if iface_match:
                current_interface = int(iface_match.group(1))
                # The next two lines are a header, so skip them
                next(ipv4_lines)
                next(ipv4_lines)
            else:
                group_match = cls._windows_netsh_group_regex.match(line)
                assert group_match, "Unknown netsh result format"
                assert current_interface is not None, "Unexpected netsh address line"
                count, addr = group_match.groups()
                count = int(count)
                addr = ipaddress.ip_address(addr)
                interface_index_addresses[current_interface][addr] = count
        # Remove interface index 1, as that's the loopback address (and it will cause
        # the Powershell pipeline to fail).
        interface_index_addresses.pop(1)
        # Now to map the interface indexes to GUIDs
        interface_indexes = ",".join(str(i) for i in interface_index_addresses.keys())
        mapping_command = [
            "powershell.exe",
            (
                f"Get-NetAdapter -InterfaceIndex {interface_indexes} -IncludeHidden | "
                "Select-Object -Property InterfaceGuid,InterfaceIndex | "
                "ConvertTo-Json"
            ),
        ]
        mapping_ret = subprocess.run(
            mapping_command, stdout=subprocess.PIPE, check=True, encoding="utf-8"
        )
        # The output is a JSON list of objects, each object having the GUID and the
        # index.
        interface_addresses: typing.MutableMapping[
            str, typing.MutableMapping[IPAddress, int]
        ] = collections.defaultdict(dict)
        for interface_info in json.loads(mapping_ret.stdout):
            guid = interface_info["InterfaceGuid"]
            index = interface_info["InterfaceIndex"]
            interface_addresses[guid] = interface_index_addresses[index]
        assert len(interface_addresses) == len(
            interface_index_addresses
        ), "Mismatch when mapping interface indexes to GUIDs"
        return interface_addresses

    @classmethod
    def get_multicast_groups(cls) -> InterfaceGroupCount:
        """Get the current multicast groups this host has joined.

        This method will raise a pytest.skip exception for unsupported platforms
        (currently only Linux and Windows are supported for this test).

        A mapping of interface names to lists of multicast IP addresses is returned.
        """
        platform_methods = {
            "Windows": cls._get_multicast_groups_windows,
            "Linux": cls._get_multicast_groups_linux,
        }
        try:
            return platform_methods[platform.system()]()
        except KeyError:
            pytest.skip("Multicast testing not supported on this platform.")
            # This next line won't be reached, but it satisfies the type checker
            raise

    def test_multicast_join_any(self):
        before_counts = self.get_multicast_groups()
        with mcast_socket(None) as sock:
            during_counts = self.get_multicast_groups()
        after_counts = self.get_multicast_groups()
        # Just sum everything in each set of counts for the mDNS address.
        mdns_addr = ipaddress.IPv4Address("224.0.0.251")
        before_sum = sum(d.get(mdns_addr, 0) for d in before_counts.values())
        during_sum = sum(d.get(mdns_addr, 0) for d in during_counts.values())
        after_sum = sum(d.get(mdns_addr, 0) for d in after_counts.values())
        assert before_sum < during_sum
        assert after_sum < during_sum

    @pytest.mark.parametrize("interface", netifaces.interfaces())
    def test_multicast_join(self, interface):
        # Just pick an address from the interface
        for address_dict in netifaces.ifaddresses(interface).get(netifaces.AF_INET, []):
            if "addr" in address_dict:
                address = address_dict["addr"]
                break
        else:
            pytest.skip(f"Unable to find an address for interface {interface}")
            return
        before_counts = self.get_multicast_groups()
        with mcast_socket(address) as sock:
            during_counts = self.get_multicast_groups()
        after_counts = self.get_multicast_groups()

        mdns_addr = ipaddress.IPv4Address("224.0.0.251")
        before_mdns_count = before_counts[interface][mdns_addr]
        during_mdns_count = during_counts[interface][mdns_addr]
        after_mdns_count = after_counts[interface][mdns_addr]
        assert before_mdns_count < during_mdns_count
        assert after_mdns_count < during_mdns_count