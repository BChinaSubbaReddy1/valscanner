#!/usr/bin/env python3
import ipaddress
import json
import os
import queue
import re
import selectors
import socket
import socketserver
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit


POLICY_FILE = os.environ.get("EGRESS_POLICY_FILE", "/etc/browser-egress/policy.json")
LISTEN_HOST = os.environ.get("EGRESS_LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = 3128
MAX_CONNECTIONS = 16
MAX_TOTAL_CONNECTIONS = 256
MAX_HEADER_BYTES = 65536
MAX_HEADER_COUNT = 100
MAX_LINE_BYTES = 8192
MAX_TUNNEL_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_TUNNEL_SECONDS = 120
IDLE_TIMEOUT_SECONDS = 15
MAX_REQUEST_SECONDS = 30
DNS_TIMEOUT_SECONDS = 3
MAX_PENDING_BYTES_PER_SOCKET = 65536
METADATA_ADDRESSES = {
    "100.100.100.200",
    "168.63.129.16",
    "169.254.169.254",
    "169.254.170.2",
    "fd00:ec2::254",
}


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class ParsedPolicy:
    scan_id: str
    expires_at: datetime
    deadline_monotonic: float
    origins: dict


def effective_address(address):
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def prohibited_address(address):
    effective = effective_address(address)
    return (
        effective.is_unspecified
        or effective.is_loopback
        or effective.is_link_local
        or effective.is_multicast
        or effective.compressed.lower() in METADATA_ADDRESSES
    )


def canonical_host(host):
    if not isinstance(host, str) or not host:
        raise PolicyError("invalid host")
    host = host.rstrip(".")
    try:
        return ipaddress.ip_address(host.strip("[]")).compressed.lower()
    except ValueError:
        try:
            result = host.encode("idna").decode("ascii").lower()
        except UnicodeError as error:
            raise PolicyError("invalid hostname") from error
        if (len(result) > 253 or any(
                not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in result.split("."))):
            raise PolicyError("invalid hostname")
        return result


def parse_policy(path, now=None, expected_scan_id=None):
    try:
        with open(path, "r", encoding="utf-8") as policy_file:
            policy = json.load(policy_file)
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyError("policy unavailable or malformed") from error
    if not isinstance(policy, dict) or set(policy) != {"scan_id", "expires_at", "origins"}:
        raise PolicyError("invalid policy shape")
    scan_id = policy["scan_id"]
    if not isinstance(scan_id, str) or not scan_id or len(scan_id) > 128:
        raise PolicyError("invalid scan identifier")
    if expected_scan_id is not None and scan_id != expected_scan_id:
        raise PolicyError("policy scan identifier does not match gateway")
    try:
        expiry = datetime.fromisoformat(policy["expires_at"].replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError) as error:
        raise PolicyError("invalid policy expiry") from error
    current_time = now or datetime.now(timezone.utc)
    if expiry.tzinfo is None or expiry <= current_time:
        raise PolicyError("policy expired")
    origins = policy["origins"]
    if not isinstance(origins, list) or not origins or len(origins) > 32:
        raise PolicyError("invalid origin list")
    parsed = {}
    for origin in origins:
        expected_fields = {
            "scheme", "host", "port", "addresses", "private_target_authorized"
        }
        if not isinstance(origin, dict) or set(origin) != expected_fields:
            raise PolicyError("invalid origin policy")
        scheme = origin["scheme"]
        if scheme not in ("http", "https"):
            raise PolicyError("unsupported scheme")
        host = canonical_host(origin["host"])
        port = origin["port"]
        if type(port) is not int or port < 1 or port > 65535:
            raise PolicyError("invalid port")
        addresses = origin["addresses"]
        if not isinstance(addresses, list) or not addresses or len(addresses) > 64:
            raise PolicyError("invalid address policy")
        private_authorized = origin["private_target_authorized"]
        if type(private_authorized) is not bool:
            raise PolicyError("invalid private target authorization")
        allowed = set()
        for value in addresses:
            if not isinstance(value, str):
                raise PolicyError("invalid authorized address")
            try:
                address = ipaddress.ip_address(value)
            except (TypeError, ValueError) as error:
                raise PolicyError("invalid authorized address") from error
            effective = effective_address(address)
            if prohibited_address(address):
                raise PolicyError("prohibited authorized address")
            if not effective.is_global and not private_authorized:
                raise PolicyError("private address requires explicit lab authorization")
            allowed.add(address.compressed.lower())
        key = (scheme, host, port)
        if key in parsed:
            raise PolicyError("duplicate origin")
        parsed[key] = allowed
    deadline_monotonic = time.monotonic() + (expiry - current_time).total_seconds()
    return ParsedPolicy(scan_id, expiry, deadline_monotonic, parsed)


_resolver_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)


def resolve_addresses(host):
    if not _resolver_slots.acquire(blocking=False):
        raise PolicyError("DNS resolver capacity reached")
    result_queue = queue.Queue(maxsize=1)

    def resolve():
        try:
            answers = {
                ipaddress.ip_address(item[4][0])
                for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
            }
            result_queue.put((answers, None))
        except (OSError, ValueError) as error:
            result_queue.put((None, error))
        finally:
            _resolver_slots.release()

    resolver = threading.Thread(target=resolve, daemon=True)
    try:
        resolver.start()
    except RuntimeError as error:
        _resolver_slots.release()
        raise PolicyError("DNS resolver unavailable") from error
    try:
        answers, error = result_queue.get(timeout=DNS_TIMEOUT_SECONDS)
    except queue.Empty as error:
        raise PolicyError("destination resolution timed out") from error
    if error is not None:
        raise PolicyError("destination resolution failed") from error
    return answers


def validated_addresses(host, explicitly_allowed):
    try:
        literal = ipaddress.ip_address(host)
        answers = {literal}
    except ValueError:
        answers = resolve_addresses(host)
    if not answers:
        raise PolicyError("destination did not resolve")
    normalized = {address.compressed.lower() for address in answers}
    for address in answers:
        effective = effective_address(address)
        if prohibited_address(address):
            raise PolicyError("destination resolves to a prohibited address")
        if not effective.is_global and address.compressed.lower() not in explicitly_allowed:
            raise PolicyError("destination resolves to an unauthorized private address")
    if not normalized.issubset(explicitly_allowed):
        raise PolicyError("DNS answers exceed the explicitly authorized address set")
    return sorted(normalized)


class Gateway:
    def __init__(self, policy_file, expected_scan_id=None, policy=None):
        self.policy_file = policy_file
        self.expected_scan_id = expected_scan_id
        self.policy = policy
        self.budget_lock = threading.Lock()
        self.total_connections = 0
        self.total_bytes = 0

    def reserve_connection(self):
        with self.budget_lock:
            if self.total_connections >= MAX_TOTAL_CONNECTIONS:
                return False
            self.total_connections += 1
            return True

    def record_bytes(self, count):
        with self.budget_lock:
            if self.total_bytes + count > MAX_TOTAL_BYTES:
                return False
            self.total_bytes += count
            return True

    def handle(self, client):
        if not self.reserve_connection():
            self.reply(client, 429, "scan connection budget reached")
            return
        deadline = time.monotonic() + MAX_REQUEST_SECONDS
        try:
            client.settimeout(IDLE_TIMEOUT_SECONDS)
            request_line = self.read_line(client, deadline)
            parts = request_line.decode("ascii").strip().split(" ")
            if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
                raise PolicyError("malformed request line")
            method, target, _ = parts
            headers, length = self.read_headers(client, deadline)
            if length:
                raise PolicyError("request bodies are not allowed")
            if any(name.lower() == "transfer-encoding" for name, _ in headers):
                raise PolicyError("transfer-encoded requests are not allowed")
            policy = self.policy
            if policy is None:
                policy = parse_policy(
                    self.policy_file,
                    expected_scan_id=self.expected_scan_id,
                )
            if method == "CONNECT":
                scheme, host, port, path = self.parse_authority(target, "https")
                addresses, expiry = self.authorize(policy, scheme, host, port)
                self.connect_tunnel(client, addresses, port, expiry, deadline)
            elif method in ("GET", "HEAD"):
                self.forward_http(client, policy, method, target, headers, deadline)
            else:
                self.reply(client, 405, "method not permitted")
        except (PolicyError, UnicodeError, OSError, ValueError) as error:
            self.reply(client, 403 if isinstance(error, PolicyError) else 400, str(error))

    def read_line(self, client, deadline):
        line = bytearray()
        while len(line) <= MAX_LINE_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PolicyError("request deadline exceeded")
            client.settimeout(min(IDLE_TIMEOUT_SECONDS, remaining))
            value = client.recv(1)
            if not value:
                raise PolicyError("incomplete request")
            line.extend(value)
            if line.endswith(b"\r\n"):
                return bytes(line[:-2])
        raise PolicyError("request line too long")

    def read_headers(self, client, deadline):
        headers = []
        total = 0
        while True:
            line = self.read_line(client, deadline)
            total += len(line) + 2
            if total > MAX_HEADER_BYTES:
                raise PolicyError("headers too large")
            if not line:
                break
            if len(headers) >= MAX_HEADER_COUNT or b":" not in line:
                raise PolicyError("invalid headers")
            name, value = line.split(b":", 1)
            if (not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                    or any((byte < 32 and byte != 9) or byte == 127 for byte in value)):
                raise PolicyError("invalid header characters")
            try:
                headers.append((name.decode("ascii"), value.decode("latin-1").strip()))
            except UnicodeError as error:
                raise PolicyError("invalid header encoding") from error
        content_length = 0
        content_length_seen = False
        host_header_seen = False
        for name, value in headers:
            if name.lower() == "content-length":
                if content_length_seen:
                    raise PolicyError("duplicate content length")
                content_length_seen = True
                try:
                    content_length = int(value)
                except ValueError as error:
                    raise PolicyError("invalid content length") from error
                if content_length < 0:
                    raise PolicyError("invalid content length")
            elif name.lower() == "host":
                if host_header_seen:
                    raise PolicyError("duplicate Host header")
                host_header_seen = True
        return headers, content_length

    def parse_authority(self, authority, scheme):
        parsed = urlsplit("//" + authority)
        if (parsed.username is not None or parsed.password is not None or parsed.path
                or parsed.query or parsed.fragment or parsed.netloc.endswith(":")):
            raise PolicyError("invalid CONNECT authority")
        host = canonical_host(parsed.hostname)
        try:
            port = parsed.port
        except ValueError as error:
            raise PolicyError("invalid destination port") from error
        if port is None:
            port = 443 if scheme == "https" else 80
        elif port < 1:
            raise PolicyError("invalid destination port")
        return scheme, host, port, "/"

    def authorize(self, policy, scheme, host, port):
        key = (scheme, canonical_host(host), port)
        allowed = policy.origins.get(key)
        if allowed is None:
            raise PolicyError("destination is outside the authorized origin policy")
        addresses = validated_addresses(key[1], allowed)
        if time.monotonic() >= policy.deadline_monotonic:
            raise PolicyError("policy expired during destination validation")
        return addresses, policy.deadline_monotonic

    def pinned_socket(self, addresses, port, expires_at, deadline):
        last_error = None
        for value in addresses:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PolicyError("request deadline exceeded")
            if time.monotonic() >= expires_at:
                raise PolicyError("policy expired before destination connection")
            address = ipaddress.ip_address(value)
            family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
            upstream = socket.socket(family, socket.SOCK_STREAM)
            upstream.settimeout(min(
                IDLE_TIMEOUT_SECONDS,
                remaining,
                expires_at - time.monotonic(),
            ))
            try:
                sockaddr = (value, port, 0, 0) if family == socket.AF_INET6 else (value, port)
                upstream.connect(sockaddr)
                if time.monotonic() >= expires_at:
                    raise PolicyError("policy expired during destination connection")
                return upstream
            except (OSError, PolicyError) as error:
                last_error = error
                upstream.close()
                if isinstance(error, PolicyError):
                    raise
        raise OSError("no validated destination address could be reached") from last_error

    def forward_http(self, client, policy, method, target, headers, deadline):
        parsed = urlsplit(target)
        if (not parsed.scheme or not parsed.netloc or parsed.netloc.endswith(":")
                or "#" in target or parsed.username is not None):
            raise PolicyError("absolute-form HTTP proxy URL required")
        scheme = parsed.scheme.lower()
        if scheme != "http":
            raise PolicyError("HTTPS must use CONNECT")
        host = canonical_host(parsed.hostname)
        try:
            port = parsed.port
        except ValueError as error:
            raise PolicyError("invalid destination port") from error
        if port is None:
            port = 80
        elif port < 1:
            raise PolicyError("invalid destination port")
        addresses, expiry = self.authorize(policy, scheme, host, port)
        upstream = self.pinned_socket(addresses, port, expiry, deadline)
        try:
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
            header_bytes = []
            host_seen = False
            for name, value in headers:
                if name.lower() in ("proxy-authorization", "proxy-connection", "connection"):
                    continue
                if name.lower() == "host":
                    host_seen = True
                    _, header_host, header_port, _ = self.parse_authority(value, "http")
                    if header_host != host or header_port != port:
                        raise PolicyError("Host header does not match destination")
                header_bytes.append(f"{name}: {value}\r\n".encode("latin-1"))
            if not host_seen:
                header_bytes.append(f"Host: {parsed.netloc}\r\n".encode("ascii"))
            upstream.sendall(f"{method} {path} HTTP/1.1\r\n".encode("ascii")
                             + b"".join(header_bytes) + b"Connection: close\r\n\r\n")
            self.relay(client, upstream, expiry)
        finally:
            upstream.close()

    def connect_tunnel(self, client, addresses, port, expiry, deadline):
        upstream = self.pinned_socket(addresses, port, expiry, deadline)
        try:
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self.relay(client, upstream, expiry)
        finally:
            upstream.close()

    def relay(self, client, upstream, expiry_deadline):
        client.setblocking(False)
        upstream.setblocking(False)
        selector = selectors.DefaultSelector()
        peers = {client: upstream, upstream: client}
        pending = {client: bytearray(), upstream: bytearray()}
        read_paused = {client: False, upstream: False}
        read_eof = set()
        write_shutdown = set()
        selector.register(client, selectors.EVENT_READ)
        selector.register(upstream, selectors.EVENT_READ)
        deadline = time.monotonic() + MAX_TUNNEL_SECONDS
        transferred = 0
        last_activity = time.monotonic()

        def shutdown_write(sock):
            if sock in write_shutdown:
                return
            write_shutdown.add(sock)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        def update_events(sock):
            events = 0
            if (sock not in read_eof and not read_paused[sock]
                    and len(pending[peers[sock]]) < MAX_PENDING_BYTES_PER_SOCKET):
                events |= selectors.EVENT_READ
            if pending[sock]:
                events |= selectors.EVENT_WRITE
            if events:
                try:
                    selector.modify(sock, events)
                except KeyError:
                    selector.register(sock, events)
            else:
                try:
                    selector.unregister(sock)
                except KeyError:
                    pass

        try:
            while True:
                policy_remaining = expiry_deadline - time.monotonic()
                tunnel_remaining = deadline - time.monotonic()
                idle_remaining = IDLE_TIMEOUT_SECONDS - (time.monotonic() - last_activity)
                if policy_remaining <= 0 or tunnel_remaining <= 0 or idle_remaining <= 0:
                    return
                events = selector.select(
                    timeout=min(policy_remaining, tunnel_remaining, idle_remaining)
                )
                if not events:
                    continue
                for key, mask in events:
                    source = key.fileobj
                    if mask & selectors.EVENT_READ:
                        if time.monotonic() >= expiry_deadline:
                            return
                        try:
                            data = source.recv(16384)
                        except BlockingIOError:
                            data = None
                        if data == b"":
                            read_eof.add(source)
                            destination = peers[source]
                            if not pending[destination]:
                                shutdown_write(destination)
                            update_events(source)
                            update_events(destination)
                            if (len(read_eof) == 2
                                    and not pending[client]
                                    and not pending[upstream]):
                                return
                        if data:
                            if (time.monotonic() >= expiry_deadline
                                    or time.monotonic() >= deadline):
                                return
                            transferred += len(data)
                            if (transferred > MAX_TUNNEL_BYTES
                                    or not self.record_bytes(len(data))):
                                return
                            pending[peers[source]].extend(data)
                            last_activity = time.monotonic()
                            if len(pending[peers[source]]) >= MAX_PENDING_BYTES_PER_SOCKET:
                                read_paused[source] = True
                            update_events(peers[source])
                            update_events(source)
                    if mask & selectors.EVENT_WRITE:
                        if time.monotonic() >= expiry_deadline:
                            return
                        buffer = pending[source]
                        try:
                            sent = source.send(buffer[:16384])
                        except BlockingIOError:
                            sent = 0
                        if sent:
                            del buffer[:sent]
                            last_activity = time.monotonic()
                            source_peer = peers[source]
                            if len(buffer) < MAX_PENDING_BYTES_PER_SOCKET:
                                read_paused[source_peer] = False
                            if source_peer in read_eof and not buffer:
                                shutdown_write(source)
                            update_events(source)
                            update_events(source_peer)
                if (len(read_eof) == 2
                        and not pending[client]
                        and not pending[upstream]):
                    return
        finally:
            selector.close()

    def reply(self, client, status, message):
        body = (message[:200] + "\n").encode("utf-8", errors="replace")
        try:
            client.sendall(
                f"HTTP/1.1 {status} Error\r\nContent-Type: text/plain\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode("ascii") + body
            )
        except OSError:
            pass


class ThreadedServer(socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = MAX_CONNECTIONS

    def __init__(self, address, gateway):
        self.gateway = gateway
        self.connection_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, socketserver.BaseRequestHandler)

    def process_request(self, request, client_address):
        if not self.connection_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        thread = threading.Thread(
            target=self.process_bounded_request,
            args=(request, client_address),
            daemon=True,
        )
        try:
            thread.start()
        except RuntimeError:
            self.connection_slots.release()
            self.shutdown_request(request)
            raise

    def process_bounded_request(self, request, client_address):
        try:
            self.gateway.handle(request)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)
            self.connection_slots.release()


def main():
    policy_path = os.environ.get("EGRESS_POLICY_FILE", POLICY_FILE)
    expected_scan_id = os.environ.get("EGRESS_EXPECTED_SCAN_ID")
    policy = parse_policy(policy_path, expected_scan_id=expected_scan_id)
    server = ThreadedServer(
        (LISTEN_HOST, LISTEN_PORT),
        Gateway(
            policy_path,
            expected_scan_id=expected_scan_id,
            policy=policy,
        ),
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
