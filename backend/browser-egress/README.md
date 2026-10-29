# Browser Egress Boundary (Stage 1)

This directory defines a test-only, isolated browser-worker egress boundary. It
does not add browser automation to the scanner, change the existing Docker
stack, or provide a production policy issuer.

## Trust boundaries and topology

```text
test worker
    |
    | HTTP proxy only; no external route
    v
internal browser-worker network
    |
    v
trusted egress gateway ---- internal fixture-target network ---- local fixtures
    |
    +---- outbound bridge (gateway only)
```

The worker is attached only to an internal Docker network shared with the
gateway. Fixtures live on a different internal network shared with the
gateway. Only the gateway has an outbound bridge-network attachment. The
worker receives no policy file, does not expose a policy API, and cannot
configure or widen the gateway policy. The test policy is mounted read-only
into the gateway. This fixture is not a substitute for trusted backend
provisioning; a later integration must create a unique gateway/policy for an
approved scan from backend-owned target and organization state.

The test fixtures are bound to an expected scan ID in gateway configuration;
the gateway rejects a fixture whose ID does not match that expected value.
This detects mismatched fixture wiring but is not policy authentication. No
production issuer, signature verification, replay cache, organization binding,
or trusted backend-to-gateway channel exists here. A production issuer must
derive the exact origin and pinned address snapshot only after the backend's
authorization and target validation succeed. It should issue a canonical,
versioned policy containing issuer, unique gateway audience, scan and
organization IDs, exact scheme/host/effective port, validated address set,
private-lab authorization decision, issue/expiry times, and a unique policy
ID. The backend must sign that payload with a protected signing key; the
gateway must verify the signature against a separately provisioned public key,
match the configured gateway/scan audience, enforce a short maximum lifetime
and monotonic expiry, and reject tampered, expired, wrong-scan, wrong-audience,
or replayed provisioning IDs. Provisioning must be backend-controlled and
worker-inaccessible. Cancellation, timeout, completion, and failure must
revoke the policy and remove both gateway and worker. Until that issuer,
verification, replay handling, and lifecycle are implemented and tested,
policy provenance is an explicit integration blocker.

The gateway accepts only HTTP proxy requests and HTTPS `CONNECT`. For every
new destination it validates the exact scheme, hostname, and effective port
against the read-only policy, resolves DNS itself, requires every returned
address to be in the policy's per-origin address snapshot, validates each
address, and opens the upstream socket to a validated numeric address (not
the hostname). A changed, mixed, or otherwise unpinned DNS answer is rejected.
Policy address snapshots must contain globally routable addresses unless that
origin explicitly marks private-target authorization; private addresses are
then still restricted to the exact listed IPs. The future trusted issuer must
set that flag only when the backend's existing exact private-lab policy allows
the submitted origin. Invalid, missing, expired, or malformed policy fails
closed.

## HTTPS limitation

For `CONNECT`, the gateway enforces the HTTPS hostname and effective port
against the scan's exact origin policy and pins the tunnel's TCP destination.
This matches the scanner's current same-origin tuple (scheme, hostname,
effective port); path scope is not part of that existing same-origin rule. A
cross-origin HTTPS URL needs a separate CONNECT and is denied unless its
origin is independently authorized. The TLS tunnel is opaque: it does **not** enforce
individual URL paths, HTTP methods, redirect destinations inside the tunnel,
resource counts, or WebSocket upgrades inside TLS. This design makes no claim
that CONNECT enforces those properties. Browser request interception may
provide additional telemetry but is not the security boundary. Restricting
individual HTTPS requests would require a separately designed and tested TLS
inspection boundary; that is out of scope.

## Resource and lifecycle limits

The gateway bounds concurrent connections (16), total connections per policy
(256), request/header size, DNS resolution (3 seconds), request setup (30
seconds), tunnel idle time, tunnel lifetime (120 seconds), bytes per tunnel
(16 MiB), and total relayed bytes per policy (128 MiB). The test Compose file
also bounds worker CPU, memory, and process count. A future backend integration
must enforce the scan wall-time and worker-count budgets and guarantee
container/policy cleanup on every cancellation and failure.
Relaying uses nonblocking sockets, bounded pending buffers, and a monotonic
policy deadline so a blocked peer cannot hold a relay open past expiry.

## Run the deterministic container tests

From this directory, run:

```powershell
.\test-boundary.ps1
```

The tests use only local fixture containers. They do not contact public
targets. Docker networking and gateway behavior must be verified by this
script; unit tests alone are insufficient.

The container test runs two scan workers and gateways concurrently on separate
internal worker networks with different read-only policies. It verifies
per-policy HTTP authorization, cross-scan denial, cross-gateway reachability
denial, and that workers have no policy or host-file mounts. It exercises a
permitted local HTTPS CONNECT/TLS request through a self-signed local fixture,
with normal certificate-chain and hostname validation using the test fixture
certificate as a specifically trusted test CA, then denies a cross-scan HTTPS
destination. A third isolated gateway runs a short-lived test policy while
live HTTP and HTTPS streams remain active; both relay sockets must close
within three seconds after the policy expiry, and a new request after expiry
must receive an explicit denial. It also checks HTTP redirects,
alternate and malformed ports, malformed authorities, duplicate
`Content-Length` and `Transfer-Encoding` rejection, IPv4/IPv6 loopback policy
decisions, actual IPv6 HTTP egress through the gateway to a controlled ULA
fixture, IPv4-mapped IPv6 loopback, mixed DNS answers, DNS rebinding, direct
IPv4/IPv6 TCP and UDP probes, direct DNS queries, absence of IPv4/IPv6 default
routes, connection-capacity rejection, relay expiry under socket-pair
backpressure, idle CONNECT cleanup, cancellation, and Compose cleanup. The
TLS private key is test-only material mounted only into the TLS fixture.

Docker IPv6 is explicitly enabled and the suite reaches an actual IPv6
fixture through the gateway; prohibited and mapped-loopback addresses are
rejected by gateway policy before connection. This does not constitute a
general host firewall test for arbitrary IPv6 routing. The worker has no
external route on its internal v4/v6 networks. Direct UDP/53, UDP/443, and
other local sentinel attempts are blocked from the worker, but no QUIC
handshake is implemented or claimed. Any future browser runtime must have
QUIC disabled or be subject to a separately verified UDP egress policy.

## Production integration is intentionally absent

No scan lifecycle, approval, authorization, persistence, browser discovery, or
backend configuration is connected here. Do not mount a caller-writable
policy or expose a policy-management endpoint. Before production use, a
trusted issuer must bind an immutable, short-lived policy to an approved
target, organization, and scan; isolate each worker/gateway pair; and ensure
cancel/timeout/failure destroys the worker and policy state.

The test scan pairs prove isolation in this Compose fixture only; they do not
prove backend-owned policy issuance, cryptographic policy authentication,
anti-replay, or production orchestration. Read-only mounts, configured
expected scan IDs, and separate worker networks are the test trust boundary.
Cancellation is tested as worker termination followed by explicit Compose
cleanup, not as an integrated scan lifecycle.
HTTPS CONNECT constrains destination host, port, and pinned TCP address only.
It cannot enforce encrypted request paths, methods, redirects, or resource
counts. If browser discovery requires request-level scope, a separately
verified TLS inspection mechanism is a prerequisite. The current scanner
enforces same-origin at scheme/host/effective-port level, so CONNECT can
enforce that origin boundary but cannot provide the request and page budgets
inside an HTTPS session. Production policy provenance, anti-replay, real
browser lifecycle cleanup, and a deliberate QUIC policy remain blockers to
Stage 2.
