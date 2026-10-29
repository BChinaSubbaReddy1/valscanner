#!/usr/bin/env python3
import json
import os
from datetime import datetime, timezone

from gateway import Gateway, LISTEN_HOST, LISTEN_PORT, ThreadedServer, parse_policy


def main():
    expires_at = os.environ["BOUNDARY_EXPIRES_AT"]
    expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    policy_path = "/tmp/expiry-policy.json"
    policy = {
        "scan_id": "integration-expiry-fixture",
        "expires_at": expiry.astimezone(timezone.utc).isoformat(),
        "origins": [
            {
                "scheme": "http",
                "host": "fixture-target.test",
                "port": 8080,
                "addresses": ["172.31.0.10"],
                "private_target_authorized": True,
            },
            {
                "scheme": "https",
                "host": "fixture-target.test",
                "port": 8443,
                "addresses": ["172.31.0.10"],
                "private_target_authorized": True,
            },
        ],
    }
    with open(policy_path, "w", encoding="utf-8") as policy_file:
        json.dump(policy, policy_file)
    expected_scan_id = os.environ["EGRESS_EXPECTED_SCAN_ID"]
    parsed_policy = parse_policy(policy_path, expected_scan_id=expected_scan_id)
    ThreadedServer(
        (LISTEN_HOST, LISTEN_PORT),
        Gateway(
            policy_path,
            expected_scan_id=expected_scan_id,
            policy=parsed_policy,
        ),
    ).serve_forever()


if __name__ == "__main__":
    main()
