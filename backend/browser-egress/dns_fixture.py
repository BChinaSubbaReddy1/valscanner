#!/usr/bin/env python3
import socket
import socketserver
import struct
import threading


_lock = threading.Lock()
_rebind_lookups = 0
_addresses = {
    "fixture-target.test": ["172.31.0.10"],
    "fixture-decoy.test": ["172.31.0.11"],
    "egress-sentinel.test": ["172.32.0.10"],
    "mixed.fixture.test": ["172.31.0.10", "127.0.0.1"],
}
_ipv6_addresses = {
    "fixture-ipv6.test": ["fd42:31::10"],
}


def parse_name(packet, offset):
    labels = []
    while True:
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise ValueError("compressed query name is unsupported")
        labels.append(packet[offset:offset + length].decode("ascii").lower())
        offset += length
    return ".".join(labels), offset


class DnsHandler(socketserver.BaseRequestHandler):
    def handle(self):
        global _rebind_lookups
        packet, transport = self.request
        if len(packet) < 17:
            return
        try:
            name, offset = parse_name(packet, 12)
            query_type, query_class = struct.unpack("!HH", packet[offset:offset + 4])
        except (IndexError, UnicodeError, ValueError, struct.error):
            return
        if query_class != 1:
            answers = []
        elif query_type == 28:
            answers = _ipv6_addresses.get(name, [])
        elif query_type != 1:
            answers = []
        elif name == "rebind.fixture.test":
            with _lock:
                _rebind_lookups += 1
                address = "172.31.0.10" if _rebind_lookups == 1 else "172.31.0.11"
            answers = [address]
        else:
            answers = _addresses.get(name, [])
        response_flags = 0x8180 if (
            answers
            or name in _addresses
            or name in _ipv6_addresses
            or name == "rebind.fixture.test"
        ) else 0x8183
        transaction_id = struct.unpack("!H", packet[:2])[0]
        header = struct.pack("!HHHHHH", transaction_id, response_flags, 1, len(answers), 0, 0)
        question = packet[12:offset + 4]
        answer_type = query_type
        records = b"".join(
            b"\xc0\x0c" + struct.pack("!HHIH", answer_type, 1, 0, len(
                socket.inet_pton(socket.AF_INET6 if answer_type == 28 else socket.AF_INET, address)
            ))
            + socket.inet_pton(socket.AF_INET6 if answer_type == 28 else socket.AF_INET, address)
            for address in answers
        )
        transport.sendto(header + question + records, self.client_address)


class DnsServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


DnsServer(("0.0.0.0", 53), DnsHandler).serve_forever()
