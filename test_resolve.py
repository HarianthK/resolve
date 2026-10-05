# Run: python test_resolve.py. The first check is offline; the second asks the real root servers.
import socket
import struct

import resolve

# A reply built by hand: question example.com A, one CNAME answer whose target reuses the
# question's name through a compression pointer, one MX and one TXT record.
question = b"\x07example\x03com\x00" + struct.pack("!HH", resolve.A, 1)
cname = b"\xc0\x0c" + struct.pack("!HHIH", resolve.CNAME, 1, 60, 6) + b"\x03www\xc0\x0c"  # www.example.com
mx = b"\xc0\x0c" + struct.pack("!HHIH", resolve.MX, 1, 60, 9) + struct.pack("!H", 10) + b"\x04mail\xc0\x0c"
txt = b"\xc0\x0c" + struct.pack("!HHIH", resolve.TXT, 1, 60, 8) + b"\x02hi\x04v=s1"
packet = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 3, 0, 0) + question + cname + mx + txt

reply = resolve.parse(packet)
assert reply["id"] == 0x1234 and reply["rcode"] == 0 and not reply["truncated"]
assert [r["type"] for r in reply["answers"]] == [resolve.CNAME, resolve.MX, resolve.TXT]
assert reply["answers"][0]["name"] == "example.com"
assert reply["answers"][0]["value"] == "www.example.com", reply["answers"][0]["value"]
assert reply["answers"][1]["value"] == "10 mail.example.com", reply["answers"][1]["value"]
assert reply["answers"][2]["value"] == "'hi' 'v=s1'", reply["answers"][2]["value"]
assert reply["answers"][2]["ttl"] == 60

# The packet with the truncation bit set must say so, since that decides the TCP retry.
assert resolve.parse(struct.pack("!HHHHHH", 1, 0x8380, 0, 0, 0, 0))["truncated"]

# The cache, offline: a scripted network that counts every packet, and a clock that jumps.
# The root refers .com, .com refers example.com, and example.com answers with a 300s TTL.
ROOT_IPS = set(resolve.ROOTS.values())
packets = []


def fake_ask(server, name, qtype=resolve.A, timeout=3, verbose=False):
    packets.append(server)
    ns = lambda zone, host, ttl: {"name": zone, "type": resolve.NS, "ttl": ttl, "value": host}
    glue = lambda host, ip: {"name": host, "type": resolve.A, "ttl": 172800, "value": ip}
    empty = {"id": 0, "rcode": 0, "truncated": False, "answers": [], "authority": [], "additional": []}
    if server in ROOT_IPS:
        return dict(empty, authority=[ns("com", "a.gtld", 172800)], additional=[glue("a.gtld", "10.0.0.1")])
    if server == "10.0.0.1":
        return dict(empty, authority=[ns("example.com", "ns.example.com", 3600)],
                    additional=[glue("ns.example.com", "10.0.0.2")])
    assert server == "10.0.0.2", server
    return dict(empty, answers=[{"name": name, "type": resolve.A, "ttl": 300, "value": "93.184.216.34"}])


now = [1000.0]
real_ask, real_clock = resolve.ask, resolve.clock
resolve.ask, resolve.clock = fake_ask, (lambda: now[0])
resolve.answers.clear()
resolve.known.clear()
resolve.known[""] = (float("inf"), list(ROOT_IPS))
try:
    def lookup():
        packets.clear()
        return resolve.resolve("example.com")

    first = lookup()
    assert first[0]["value"] == "93.184.216.34" and len(packets) == 3, packets
    # Asked again at once: no packets, and the answer shows the time it has left.
    now[0] += 100
    again = lookup()
    assert packets == [], packets
    assert again[0]["ttl"] == 200, again
    # The answer has expired but example.com's name servers have not: one packet, to them.
    now[0] += 250
    lookup()
    assert packets == ["10.0.0.2"], packets
    # An hour on, example.com's referral has expired too, but .com's has not.
    now[0] += 3600
    lookup()
    assert packets == ["10.0.0.1", "10.0.0.2"], packets
finally:
    resolve.ask, resolve.clock = real_ask, real_clock
    resolve.answers.clear()
    resolve.known.clear()
    resolve.known[""] = (float("inf"), list(ROOT_IPS))

# Names that do not exist, offline. The .com server says NXDOMAIN and, as RFC 2308 asks,
# sends its SOA: a TTL of 900 and a minimum of 3600, so the miss is good for 900 seconds.
def missing_ask(server, name, qtype=resolve.A, timeout=3, verbose=False):
    packets.append(server)
    empty = {"id": 0, "rcode": 0, "truncated": False, "answers": [], "authority": [], "additional": []}
    if server in ROOT_IPS:
        return dict(empty, authority=[{"name": "com", "type": resolve.NS, "ttl": 172800, "value": "a.gtld"}],
                    additional=[{"name": "a.gtld", "type": resolve.A, "ttl": 172800, "value": "10.0.0.1"}])
    soa = {"name": "com", "type": resolve.SOA, "ttl": 900, "value": "a.gtld x 1 2 3 4 3600", "minimum": 3600}
    return dict(empty, rcode=3, authority=[] if name.startswith("bare") else [soa])


def misses(name, qtype=resolve.A):
    packets.clear()
    try:
        resolve.resolve(name, qtype)
    except LookupError as e:
        assert "does not exist" in str(e), e
        return list(packets)
    raise AssertionError(f"{name} resolved")


now[0] = 5000.0
resolve.ask, resolve.clock = missing_ask, (lambda: now[0])
try:
    assert len(misses("nope.com")) == 2
    now[0] += 100
    assert misses("nope.com") == [], "a fresh miss should come from the cache"
    assert misses("nope.com", resolve.AAAA) == [], "a missing name is missing for every type"
    # Past the 900 seconds: asked again, though only of .com, whose referral is still good.
    now[0] += 850
    assert misses("nope.com") == ["10.0.0.1"], packets
    # A miss that arrives without an SOA gives no time to keep it, so it is not kept.
    misses("bare.com")
    assert misses("bare.com") == ["10.0.0.1"], packets
finally:
    resolve.ask, resolve.clock = real_ask, real_clock
    resolve.answers.clear()
    resolve.missing.clear()
    resolve.known.clear()
    resolve.known[""] = (float("inf"), list(ROOT_IPS))

# Failover, offline: .com has three servers and the first two asked time out. The lookup
# still succeeds, and each server is asked once. With all three silent, it says so.
dead = set()


def flaky_ask(server, name, qtype=resolve.A, timeout=3, verbose=False):
    packets.append(server)
    if server in dead: raise socket.timeout("timed out")
    empty = {"id": 0, "rcode": 0, "truncated": False, "answers": [], "authority": [], "additional": []}
    if server in ROOT_IPS:
        return dict(empty, authority=[{"name": "com", "type": resolve.NS, "ttl": 172800, "value": f"{c}.gtld"} for c in "abc"],
                    additional=[{"name": f"{c}.gtld", "type": resolve.A, "ttl": 172800, "value": f"10.0.1.{i}"} for i, c in enumerate("abc")])
    return dict(empty, answers=[{"name": name, "type": resolve.A, "ttl": 60, "value": "10.9.9.9"}])


resolve.ask = flaky_ask
try:
    for alive in ["10.0.1.0", "10.0.1.1", "10.0.1.2"]:
        resolve.known.clear()
        resolve.known[""] = (float("inf"), list(ROOT_IPS))
        resolve.answers.clear()
        dead = {"10.0.1.0", "10.0.1.1", "10.0.1.2"} - {alive}
        packets.clear()
        assert resolve.resolve("example.com")[0]["value"] == "10.9.9.9"
        gtld = packets[1:]
        assert gtld[-1] == alive and len(gtld) == len(set(gtld)) <= 3, packets
    resolve.answers.clear()
    dead = {"10.0.1.0", "10.0.1.1", "10.0.1.2"}
    try:
        resolve.resolve("example.com")
        raise AssertionError("resolved with every server down")
    except LookupError as e:
        assert "none of the 3 servers" in str(e), e
finally:
    resolve.ask = real_ask
    resolve.answers.clear()
    resolve.known.clear()
    resolve.known[""] = (float("inf"), list(ROOT_IPS))

# Bailiwick, offline: a hostile .com server tries four lies when asked about a name under
# .com. Each must fail the lookup or be ignored, and none may end up in the cache.
lie = None


def hostile_ask(server, name, qtype=resolve.A, timeout=3, verbose=False):
    packets.append(server)
    assert len(packets) < 20, "the resolver is going round in circles"
    empty = {"id": 0, "rcode": 0, "truncated": False, "answers": [], "authority": [], "additional": []}
    ns = lambda zone, host: {"name": zone, "type": resolve.NS, "ttl": 172800, "value": host}
    glue = lambda host, ip: {"name": host, "type": resolve.A, "ttl": 172800, "value": ip}
    if server in ROOT_IPS:
        if name.endswith(".org"): return dict(empty, rcode=3)
        return dict(empty, authority=[ns("com", "a.gtld")], additional=[glue("a.gtld", "10.0.0.1")])
    assert server == "10.0.0.1", f"asked {server}, an address only a lie gave"
    if lie == "other name":
        return dict(empty, answers=[{"name": "bank.com", "type": resolve.A, "ttl": 300, "value": "6.6.6.6"}])
    if lie == "sideways":
        return dict(empty, authority=[ns("bank.org", "ns.bank.org")], additional=[glue("ns.bank.org", "6.6.6.6")])
    if lie == "upward":
        # Glue inside .com, so only the referral check can stop it, not the glue check.
        return dict(empty, authority=[ns("com", "ns.com")], additional=[glue("ns.com", "10.0.0.1")])
    assert lie == "foreign glue"
    return dict(empty, authority=[ns("example.com", "ns.evil.org")], additional=[glue("ns.evil.org", "6.6.6.6")])


resolve.ask = hostile_ask
try:
    for lie in ["other name", "sideways", "upward", "foreign glue"]:
        resolve.answers.clear()
        packets.clear()
        try:
            got = resolve.resolve("example.com")
            raise AssertionError(f"{lie}: resolved to {got}")
        except LookupError:
            pass
        assert "6.6.6.6" not in packets, (lie, packets)
        assert "bank.org" not in resolve.known and not any("bank" in k[0] for k in resolve.answers), lie
finally:
    resolve.ask = real_ask
    resolve.answers.clear()
    resolve.missing.clear()
    resolve.known.clear()
    resolve.known[""] = (float("inf"), list(ROOT_IPS))

# Live: a.root-servers.net has had the same address since 1997, so both resolvers must agree.
ours = {r["value"] for r in resolve.resolve("a.root-servers.net")}
theirs = {ai[4][0] for ai in socket.getaddrinfo("a.root-servers.net", 53, socket.AF_INET)}
assert ours == theirs == {"198.41.0.4"}, (ours, theirs)
print("ok")
