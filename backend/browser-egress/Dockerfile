FROM python:3.12-alpine@sha256:5789aa194f757888f41fa3d48e14b6feaa1b57c0af0b56fcb1372d6474d3bff0

RUN addgroup -S egress && adduser -S -G egress egress
WORKDIR /opt/browser-egress
COPY --chown=egress:egress gateway.py expiry_gateway.py fixture_server.py dns_fixture.py worker_test.py worker_isolation_test.py worker_expiry_test.py worker_hold.py ./
COPY --chown=egress:egress fixture-cert.pem /opt/browser-egress/fixture-cert.pem
USER egress
ENTRYPOINT ["python", "-u"]
