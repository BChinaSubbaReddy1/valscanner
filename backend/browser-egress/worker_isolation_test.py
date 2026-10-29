#!/usr/bin/env python3
import os
import socket
import time
import urllib.error
import urllib.request


proxy = os.environ["HTTP_PROXY"]
opener = urllib.request.build_opener(
    urllib.request.ProxyHandler({"http": proxy})
)

with opener.open("http://fixture-decoy.test:8080/scan-b", timeout=5) as response:
    assert response.status == 200
    assert response.read() == b"controlled-fixture:/scan-b\n"

try:
    opener.open("http://fixture-target.test:8080/scan-a", timeout=3)
except urllib.error.HTTPError as error:
    assert error.code == 403
else:
    raise AssertionError("scan B used scan A's origin policy")

gateway_a = os.environ["SCAN_A_GATEWAY_IP"]
try:
    connection = socket.create_connection((gateway_a, 3128), timeout=1)
except OSError:
    pass
else:
    connection.close()
    raise AssertionError("scan B reached scan A's gateway")

try:
    open("/etc/browser-egress/policy.json", "w", encoding="utf-8").write("{}")
except OSError:
    pass
else:
    raise AssertionError("scan B worker altered its gateway policy")

time.sleep(5)
print("scan B policy isolation and cross-gateway checks passed")
