#!/usr/bin/env python3
import os
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone


PROXY = os.environ["HTTP_PROXY"]
EXPIRES_AT = datetime.fromisoformat(
    os.environ["BOUNDARY_EXPIRES_AT"].replace("Z", "+00:00")
)
EXPIRY_TOLERANCE_SECONDS = 3
TLS_CONTEXT = ssl.create_default_context(cafile="/opt/browser-egress/fixture-cert.pem")
results = {}
errors = []


def read_to_close(connection):
    received = bytearray()
    while True:
        data = connection.recv(65536)
        if not data:
            break
        received.extend(data)
    return bytes(received), datetime.now(timezone.utc)


def _capture(operation):
    try:
        operation()
    except Exception as error:
        errors.append(error)


def http_stream():
    connection = socket.create_connection(("172.34.0.2", 3128), timeout=5)
    connection.settimeout(55)
    connection.sendall(
        b"GET http://fixture-target.test:8080/expiry-stream HTTP/1.1\r\n"
        b"Host: fixture-target.test:8080\r\nConnection: close\r\n\r\n"
    )
    results["http"] = read_to_close(connection)
    connection.close()


def https_stream():
    proxy_connection = socket.create_connection(("172.34.0.2", 3128), timeout=5)
    proxy_connection.settimeout(55)
    proxy_connection.sendall(
        b"CONNECT fixture-target.test:8443 HTTP/1.1\r\n"
        b"Host: fixture-target.test:8443\r\n\r\n"
    )
    connect_response = bytearray()
    while b"\r\n\r\n" not in connect_response:
        data = proxy_connection.recv(4096)
        if not data:
            raise AssertionError("gateway closed before CONNECT completed")
        connect_response.extend(data)
    if not connect_response.startswith(b"HTTP/1.1 200"):
        raise AssertionError(f"CONNECT failed: {connect_response!r}")

    tls_connection = TLS_CONTEXT.wrap_socket(
        proxy_connection, server_hostname="fixture-target.test"
    )
    tls_connection.sendall(
        b"GET /expiry-stream HTTP/1.1\r\n"
        b"Host: fixture-target.test:8443\r\nConnection: close\r\n\r\n"
    )
    received = bytearray()
    while True:
        try:
            data = tls_connection.recv(65536)
        except ssl.SSLEOFError:
            break
        if not data:
            break
        received.extend(data)
    results["https"] = bytes(received), datetime.now(timezone.utc)
    tls_connection.close()


for label, operation in (("http", http_stream), ("https", https_stream)):
    thread = threading.Thread(target=lambda op=operation: _capture(op), daemon=True)
    thread.start()
    results[label + "_thread"] = thread

for label in ("http", "https"):
    thread = results[label + "_thread"]
    thread.join(timeout=55)
    if thread.is_alive():
        raise AssertionError(f"{label} relay did not close after policy expiry")
if errors:
    raise errors[0]

for label in ("http", "https"):
    response, closed_at = results[label]
    if b"200 OK" not in response or len(response) < 4096:
        raise AssertionError(f"{label} stream did not forward pre-expiry data")
    if closed_at < EXPIRES_AT:
        raise AssertionError(f"{label} relay closed before policy expiry")
    if (closed_at - EXPIRES_AT).total_seconds() > EXPIRY_TOLERANCE_SECONDS:
        raise AssertionError(f"{label} relay exceeded expiry tolerance")

if datetime.now(timezone.utc) < EXPIRES_AT:
    time.sleep((EXPIRES_AT - datetime.now(timezone.utc)).total_seconds())

opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({"http": PROXY})
)
try:
    opener.open("http://fixture-target.test:8080/after-expiry", timeout=5)
except urllib.error.HTTPError as error:
    if error.code != 403:
        raise
else:
    raise AssertionError("gateway forwarded a new request after policy expiry")

print("live HTTP and HTTPS CONNECT relays closed at policy expiry")
