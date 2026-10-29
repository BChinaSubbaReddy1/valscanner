#!/usr/bin/env python3
import os
import socket
import urllib.error
import urllib.request
import io
import json
import ssl
import threading
import time
import unittest.mock

import gateway


PROXY = os.environ["HTTP_PROXY"]
OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({"http": PROXY, "https": PROXY})
)
TLS_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({"https": PROXY}),
    urllib.request.HTTPSHandler(
        context=ssl.create_default_context(cafile="/opt/browser-egress/fixture-cert.pem")
    ),
)


def expect_denied(url, label):
    try:
        with OPENER.open(url, timeout=3) as response:
            raise AssertionError(f"{label} unexpectedly succeeded: {response.status}")
    except urllib.error.HTTPError as error:
        assert error.code in (400, 403), f"{label} returned {error.code}"
    except urllib.error.URLError as error:
        assert "Tunnel connection failed: 403" in str(error.reason), (
            f"{label} did not fail with an explicit gateway denial: {error.reason}"
        )


def expect_direct_blocked(host, port, label):
    try:
        connection = socket.create_connection((host, port), timeout=1)
    except OSError:
        return
    connection.close()
    raise AssertionError(f"direct worker connection unexpectedly succeeded: {label}")


future_policy = {
    "scan_id": "test",
    "expires_at": "2099-01-01T00:00:00Z",
    "origins": [{
        "scheme": "http",
        "host": "fixture-target.test",
        "port": 8080,
        "addresses": ["172.31.0.10"],
        "private_target_authorized": True,
    }],
}
with unittest.mock.patch("builtins.open", return_value=io.StringIO(json.dumps(future_policy))):
    parsed_policy = gateway.parse_policy("/not-mounted")
assert ("http", "fixture-target.test", 8080) in parsed_policy.origins
try:
    with unittest.mock.patch("builtins.open", return_value=io.StringIO(json.dumps(future_policy))):
        gateway.parse_policy("/wrong-scan", expected_scan_id="another-scan")
except gateway.PolicyError:
    pass
else:
    raise AssertionError("policy for another scan identity was accepted")

expired_policy = dict(future_policy, expires_at="2000-01-01T00:00:00Z")
with unittest.mock.patch("builtins.open", return_value=io.StringIO(json.dumps(expired_policy))):
    try:
        gateway.parse_policy("/expired")
    except gateway.PolicyError:
        pass
    else:
        raise AssertionError("expired policy was accepted")

unsafe_policy = dict(future_policy, origins=[{
    "scheme": "http",
    "host": "fixture-target.test",
    "port": 8080,
    "addresses": ["127.0.0.1"],
    "private_target_authorized": True,
}])
with unittest.mock.patch("builtins.open", return_value=io.StringIO(json.dumps(unsafe_policy))):
    try:
        gateway.parse_policy("/unsafe")
    except gateway.PolicyError:
        pass
    else:
        raise AssertionError("loopback policy address was accepted")

for prohibited_ip in ("::1", "fe80::1", "ff02::1", "fd00:ec2::254"):
    unsafe_policy = dict(future_policy, origins=[{
        "scheme": "http",
        "host": "fixture-target.test",
        "port": 8080,
        "addresses": [prohibited_ip],
        "private_target_authorized": True,
    }])
    with unittest.mock.patch("builtins.open", return_value=io.StringIO(json.dumps(unsafe_policy))):
        try:
            gateway.parse_policy("/unsafe-ipv6")
        except gateway.PolicyError:
            pass
        else:
            raise AssertionError(f"prohibited IPv6 address {prohibited_ip} was accepted")

mapped_loopback_policy = dict(future_policy, origins=[{
    "scheme": "http",
    "host": "fixture-target.test",
    "port": 8080,
    "addresses": ["::ffff:127.0.0.1"],
    "private_target_authorized": True,
}])
with unittest.mock.patch(
        "builtins.open", return_value=io.StringIO(json.dumps(mapped_loopback_policy))):
    try:
        gateway.parse_policy("/mapped-loopback")
    except gateway.PolicyError:
        pass
    else:
        raise AssertionError("IPv4-mapped IPv6 loopback policy was accepted")

private_without_lab_exception = dict(future_policy, origins=[{
    "scheme": "http",
    "host": "fixture-target.test",
    "port": 8080,
    "addresses": ["172.31.0.10"],
    "private_target_authorized": False,
}])
with unittest.mock.patch(
    "builtins.open", return_value=io.StringIO(json.dumps(private_without_lab_exception))):
    try:
        gateway.parse_policy("/private-without-authorization")
    except gateway.PolicyError:
        pass
    else:
        raise AssertionError("private destination without explicit authorization was accepted")

for policy_path in ("/missing",):
    with unittest.mock.patch("builtins.open", side_effect=OSError("missing")):
        try:
            gateway.parse_policy(policy_path)
        except gateway.PolicyError:
            pass
        else:
            raise AssertionError("missing policy was accepted")

with unittest.mock.patch("builtins.open", return_value=io.StringIO("{}")):
    try:
        gateway.parse_policy("/malformed")
    except gateway.PolicyError:
        pass
    else:
        raise AssertionError("malformed policy was accepted")

altered_policy = dict(future_policy, origins=[{
    "scheme": "http",
    "host": "fixture-target.test",
    "port": 8080,
    "addresses": ["::ffff:127.0.0.1"],
    "private_target_authorized": True,
}])
with unittest.mock.patch(
        "builtins.open", return_value=io.StringIO(json.dumps(altered_policy))):
    try:
        gateway.parse_policy("/altered")
    except gateway.PolicyError:
        pass
    else:
        raise AssertionError("altered policy with a prohibited address was accepted")

public_answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0))]
mixed_answer = public_answer + [
    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))
]
with unittest.mock.patch("gateway.socket.getaddrinfo", return_value=public_answer):
    assert gateway.validated_addresses("example.invalid", {"1.1.1.1"}) == ["1.1.1.1"]
with unittest.mock.patch("gateway.socket.getaddrinfo", return_value=mixed_answer):
    try:
        gateway.validated_addresses("example.invalid", {"1.1.1.1"})
    except gateway.PolicyError:
        pass
    else:
        raise AssertionError("mixed public and loopback DNS answers were accepted")

metadata_answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("168.63.129.16", 0))]
with unittest.mock.patch("gateway.socket.getaddrinfo", return_value=metadata_answer):
    try:
        gateway.validated_addresses("metadata.invalid", {"168.63.129.16"})
    except gateway.PolicyError:
        pass
    else:
        raise AssertionError("cloud metadata address was accepted")

with unittest.mock.patch(
        "gateway.socket.getaddrinfo", side_effect=[public_answer, [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))
        ]]):
    gateway.validated_addresses("rebinding.invalid", {"1.1.1.1"})
    try:
        gateway.validated_addresses("rebinding.invalid", {"1.1.1.1"})
    except gateway.PolicyError:
        pass
    else:
        raise AssertionError("DNS rebinding to loopback was accepted")

try:
    gateway.Gateway("/unused").authorize(
        gateway.ParsedPolicy(
            "test", gateway.datetime.fromisoformat("2099-01-01T00:00:00+00:00"),
            time.monotonic() + 3600,
            {("http", "fixture-target.test", 8080): {"172.31.0.10"}},
        ),
        "http", "fixture-decoy.test", 8080
    )
except gateway.PolicyError:
    pass
else:
    raise AssertionError("another origin was authorized by the scan policy")

for malformed_authority in (
    "fixture-target.test:",
    "fixture-target.test:0",
    "fixture-target.test/path",
    "user@fixture-target.test:443",
    "[::1]:",
):
    try:
        gateway.Gateway("/unused").parse_authority(malformed_authority, "https")
    except gateway.PolicyError:
        pass
    else:
        raise AssertionError(f"malformed authority was accepted: {malformed_authority}")

zero_port_gateway = gateway.Gateway("/unused")
zero_port_client, zero_port_peer = socket.socketpair()
try:
    with unittest.mock.patch.object(
            zero_port_gateway, "authorize",
            side_effect=AssertionError("port zero was normalized to the default port")):
        for malformed_url in (
            "http://fixture-target.test:0/health",
            "http://fixture-target.test:/health",
        ):
            try:
                zero_port_gateway.forward_http(
                    zero_port_client,
                    gateway.ParsedPolicy(
                        "test", gateway.datetime.fromisoformat("2099-01-01T00:00:00+00:00"),
                        time.monotonic() + 3600, {}
                    ),
                    "GET",
                    malformed_url,
                    [],
                    time.monotonic() + 3,
                )
            except gateway.PolicyError:
                pass
            else:
                raise AssertionError(f"malformed HTTP port was accepted: {malformed_url}")
finally:
    zero_port_client.close()
    zero_port_peer.close()

with OPENER.open("http://fixture-target.test:8080/health", timeout=5) as response:
    assert response.status == 200
    assert response.read() == b"controlled-fixture:/health\n"

expect_denied("http://fixture-target.test:8080/redirect-cross", "cross-origin redirect")
expect_denied("http://fixture-target.test:8080/redirect-port", "alternate-port redirect")
expect_denied("http://fixture-target.test:8080/redirect-cross-https", "cross-origin HTTPS redirect")
expect_denied("http://fixture-decoy.test:8080/secret", "cross-origin host")
expect_denied("http://fixture-target.test:8081/health", "alternate port")
expect_denied("http://127.0.0.1:8080/health", "IPv4 loopback")
expect_denied("http://[::1]:8080/health", "IPv6 loopback")
expect_denied("http://[::ffff:127.0.0.1]:8080/health", "IPv4-mapped IPv6 loopback")
expect_denied("https://fixture-target.test:8080/health", "unauthorized HTTPS origin")
expect_denied("http://mixed.fixture.test:8080/health", "mixed DNS answers")
expect_denied("https://fixture-decoy.test:8443/health", "cross-scan HTTPS origin")

with TLS_OPENER.open("https://fixture-target.test:8443/health", timeout=5) as response:
    assert response.status == 200
    assert response.read() == b"controlled-fixture:/health\n"

try:
    with OPENER.open("http://fixture-ipv6.test:8082/ipv6", timeout=5) as response:
        assert response.status == 200
        assert response.read() == b"controlled-fixture:/ipv6\n"
except urllib.error.HTTPError as error:
    raise AssertionError(f"permitted IPv6 request was denied: {error.read()!r}") from error

relay_client, client_peer = socket.socketpair()
relay_upstream, upstream_peer = socket.socketpair()
expiry = time.monotonic() + 0.25
relay_thread = threading.Thread(
    target=gateway.Gateway("/unused").relay,
    args=(relay_client, relay_upstream, expiry),
    daemon=True,
)
relay_started = time.monotonic()
relay_thread.start()
relay_thread.join(timeout=1)
assert not relay_thread.is_alive(), "relay did not stop at policy expiry"
assert time.monotonic() - relay_started < 1
relay_client.close()
relay_upstream.close()
client_peer.close()
upstream_peer.close()

backpressure_client, backpressure_peer = socket.socketpair()
backpressure_upstream, backpressure_source = socket.socketpair()
backpressure_client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
backpressure_upstream.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
backpressure_client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
backpressure_upstream.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
backpressure_expiry = time.monotonic() + 0.5
backpressure_gateway = gateway.Gateway("/unused")
backpressure_thread = threading.Thread(
    target=backpressure_gateway.relay,
    args=(backpressure_client, backpressure_upstream, backpressure_expiry),
    daemon=True,
)
backpressure_thread.start()
backpressure_sent = 0
backpressure_source.settimeout(0.1)
backpressure_send_deadline = time.monotonic() + 0.1
while time.monotonic() < backpressure_send_deadline:
    try:
        backpressure_sent += backpressure_source.send(b"x" * 16384)
    except (BlockingIOError, TimeoutError):
        break
backpressure_thread.join(timeout=2)
assert not backpressure_thread.is_alive(), "relay did not expire while a peer was backpressured"
assert backpressure_sent > 0
backpressure_client.close()
backpressure_peer.close()
backpressure_upstream.close()
backpressure_source.close()

held_connections = []
try:
    for _ in range(gateway.MAX_CONNECTIONS):
        held_connections.append(socket.create_connection(("172.30.0.2", 3128), timeout=3))
    overflow = socket.create_connection(("172.30.0.2", 3128), timeout=3)
    overflow.settimeout(3)
    assert overflow.recv(1) == b"", "gateway accepted beyond its concurrent connection cap"
    overflow.close()
finally:
    for connection in held_connections:
        connection.close()

timeout_probe = socket.create_connection(("172.30.0.2", 3128), timeout=3)
timeout_probe.sendall(
    b"CONNECT fixture-target.test:8443 HTTP/1.1\r\n"
    b"Host: fixture-target.test:8443\r\n\r\n"
)
timeout_probe.settimeout(gateway.IDLE_TIMEOUT_SECONDS + 3)
assert b"200 Connection Established" in timeout_probe.recv(1024)
assert timeout_probe.recv(1) == b"", "idle CONNECT tunnel did not time out and close"
timeout_probe.close()
with OPENER.open("http://fixture-target.test:8080/after-timeout", timeout=5) as response:
    assert response.status == 200
    assert response.read() == b"controlled-fixture:/after-timeout\n"

with OPENER.open("http://rebind.fixture.test:8080/health", timeout=5) as response:
    assert response.status == 200
expect_denied("http://rebind.fixture.test:8080/health", "DNS rebinding")

websocket_request = socket.create_connection(("172.30.0.2", 3128), timeout=3)
websocket_request.sendall(
    b"GET http://fixture-decoy.test:8080/socket HTTP/1.1\r\n"
    b"Host: fixture-decoy.test:8080\r\nConnection: Upgrade\r\n"
    b"Upgrade: websocket\r\n\r\n"
)
assert b"403" in websocket_request.recv(1024)
websocket_request.close()

for headers in (
    b"Content-Length: 0\r\nContent-Length: 0\r\n",
    b"Transfer-Encoding: chunked\r\n",
):
    smuggling_probe = socket.create_connection(("172.30.0.2", 3128), timeout=3)
    smuggling_probe.sendall(
        b"GET http://fixture-target.test:8080/health HTTP/1.1\r\n"
        b"Host: fixture-target.test:8080\r\n" + headers + b"\r\n"
    )
    smuggling_probe.settimeout(3)
    assert b"403" in smuggling_probe.recv(1024), "ambiguous HTTP framing was accepted"
    smuggling_probe.close()

with OPENER.open("http://egress-sentinel.test:9090/health", timeout=5) as response:
    assert response.status == 200
    assert response.read() == b"controlled-fixture:/health\n"

for address, port, name in (
    ("172.31.0.10", 8080, "fixture target network"),
    ("172.31.0.11", 8080, "decoy container"),
    ("fd42:31::10", 8082, "IPv6 fixture target network"),
    ("172.32.0.10", 9090, "outbound-only sentinel"),
    ("198.51.100.1", 80, "direct IPv4 egress"),
    ("2001:db8::1", 80, "direct IPv6 egress"),
):
    expect_direct_blocked(address, port, name)

for address in filter(None, os.environ.get("BOUNDARY_BLOCKED_IPS", "").split(",")):
    for port in (3306, 8080, 8081, 2375, 2376):
        expect_direct_blocked(address, port, f"unrelated container service {address}:{port}")

for hostname in ("backend", "mysql", "vulnscanner-backend", "vulnscanner-mysql"):
    try:
        socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        continue
    raise AssertionError(f"worker unexpectedly resolved unrelated service {hostname}")

for hostname in ("fixture-target.test", "egress-sentinel.test", "example.invalid"):
    try:
        socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        continue
    raise AssertionError(f"worker unexpectedly resolved external destination {hostname}")

host_addresses = socket.getaddrinfo("host.docker.internal", None)
assert host_addresses, "Docker host gateway alias did not resolve"
print(f"host gateway probe addresses: {sorted({entry[4][0] for entry in host_addresses})}")
for port in (22, 80, 3306, 3307, 8080, 8081, 2375, 2376):
    expect_direct_blocked("host.docker.internal", port, f"host service port {port}")

for port in (22, 80, 3306, 3307, 8080, 8081, 2375, 2376):
    expect_direct_blocked("172.30.0.1", port, f"worker-network host port {port}")

expect_direct_blocked(
    os.environ["SCAN_B_GATEWAY_IP"], 3128, "other scan gateway"
)

for address, port in (
    ("172.32.0.10", 53),
    ("172.32.0.10", 443),
    ("172.32.0.10", 9999),
    ("fd42:32::10", 443),
):
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(1)
    try:
        udp.sendto(b"direct-udp-bypass-probe", (address, port))
        try:
            udp.recvfrom(1024)
        except socket.timeout:
            pass
        else:
            raise AssertionError(f"worker reached unshared UDP endpoint {address}:{port}")
    except OSError:
        pass
    finally:
        udp.close()

dns_query = bytes.fromhex(
    "0001010000010000000000000e666978747572652d746172676574"
    "04746573740000010001"
)
dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
dns_socket.settimeout(1)
try:
    dns_socket.sendto(dns_query, ("172.31.0.53", 53))
    try:
        dns_socket.recvfrom(512)
    except socket.timeout:
        pass
    else:
        raise AssertionError("worker bypassed the gateway to reach the DNS fixture")
except OSError:
    pass
finally:
    dns_socket.close()

with open("/proc/net/ipv6_route", "r", encoding="ascii") as route_file:
    ipv6_routes = route_file.read().splitlines()
ipv6_default_routes = [
    line for line in ipv6_routes
    if line.startswith("0" * 32 + " 00") and line.split()[-1] != "lo"
]
if ipv6_default_routes:
    raise AssertionError("worker has an IPv6 default route")

with open("/proc/net/route", "r", encoding="ascii") as route_file:
    ipv4_routes = route_file.read().splitlines()[1:]
if any(fields[1] == "00000000" and fields[2] == "00000000" for fields in
       (line.split() for line in ipv4_routes)):
    raise AssertionError("worker has an IPv4 default route")

print("worker policy, proxy, DNS, and direct-network checks passed")
