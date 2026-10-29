#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import ssl
import socketserver
import socket
import threading
import time


class FixtureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/expiry-stream":
            body_length = 1024 * 1024
            self.send_response(200)
            self.send_header("Content-Length", str(body_length))
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            sent = 0
            try:
                while sent < body_length:
                    chunk = b"x" * min(1024, body_length - sent)
                    self.wfile.write(chunk)
                    self.wfile.flush()
                    sent += len(chunk)
                    time.sleep(0.1)
            except OSError:
                pass
            return
        if self.path == "/redirect-cross":
            self.send_response(302)
            self.send_header("Location", "http://fixture-decoy.test:8080/secret")
            self.end_headers()
            return
        if self.path == "/redirect-port":
            self.send_response(302)
            self.send_header("Location", "http://fixture-target.test:8081/secret")
            self.end_headers()
            return
        if self.path == "/redirect-cross-https":
            self.send_response(302)
            self.send_header("Location", "https://fixture-decoy.test:8443/secret")
            self.end_headers()
            return
        body = f"controlled-fixture:{self.path}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


class UdpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, connection = self.request
        connection.sendto(b"controlled-udp-response", self.client_address)


class IPv6HTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


http_port = int(os.environ.get("HTTP_PORT", "8080"))
http_server = ThreadingHTTPServer(("0.0.0.0", http_port), FixtureHandler)
threading.Thread(target=http_server.serve_forever, daemon=True).start()

ipv6_port = int(os.environ.get("IPV6_HTTP_PORT", "0"))
if ipv6_port:
    ipv6_server = IPv6HTTPServer(("::", ipv6_port), FixtureHandler)
    threading.Thread(target=ipv6_server.serve_forever, daemon=True).start()

tls_port = int(os.environ.get("TLS_PORT", "0"))
if tls_port:
    tls_server = ThreadingHTTPServer(("0.0.0.0", tls_port), FixtureHandler)
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.load_cert_chain(
        os.environ["TLS_CERT_FILE"], os.environ["TLS_KEY_FILE"]
    )
    tls_server.socket = tls_context.wrap_socket(tls_server.socket, server_side=True)
    threading.Thread(target=tls_server.serve_forever, daemon=True).start()

udp_ports = [value for value in os.environ.get("UDP_PORTS", "").split(",") if value]
for udp_port in udp_ports:
    udp_server = socketserver.UDPServer(("0.0.0.0", int(udp_port)), UdpHandler)
    threading.Thread(target=udp_server.serve_forever, daemon=True).start()
http_server.serve_forever()
