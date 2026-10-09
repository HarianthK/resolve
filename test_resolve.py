# Run: python test_resolve.py. The first check is offline; the second asks the real root servers.
import socket
import struct
import threading

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
        if name.split(".")[-1] == "org": return dict(empty, rcode=3)
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

# No glue, offline: example.com's referral names two servers and gives no addresses. The
# first name no longer exists, so the second must be looked up instead of the lookup failing.
def glueless_ask(server, name, qtype=resolve.A, timeout=3, verbose=False):
    packets.append((server, name))
    empty = {"id": 0, "rcode": 0, "truncated": False, "answers": [], "authority": [], "additional": []}
    ns = lambda zone, host: {"name": zone, "type": resolve.NS, "ttl": 3600, "value": host}
    a = lambda host, ip: {"name": host, "type": resolve.A, "ttl": 3600, "value": ip}
    if server in ROOT_IPS:
        if name.split(".")[-1] in gone: return dict(empty, rcode=3)
        if name.split(".")[-1] == "net": return dict(empty, authority=[ns("net", "a.gtld.net")], additional=[a("a.gtld.net", "10.0.0.5")])
        return dict(empty, authority=[ns("com", "a.gtld.com")], additional=[a("a.gtld.com", "10.0.0.1")])
    if server == "10.0.0.1":
        return dict(empty, authority=[ns("example.com", "ns1.gone.org"), ns("example.com", "ns2.ok.net")])
    if server == "10.0.0.5":
        return dict(empty, answers=[a("ns2.ok.net", "10.0.0.9")])
    assert server == "10.0.0.9", server
    return dict(empty, answers=[a(name, "93.184.216.34")])


gone = {"org"}
resolve.ask = glueless_ask
try:
    packets.clear()
    assert resolve.resolve("example.com")[0]["value"] == "93.184.216.34"
    assert any(n == "ns1.gone.org" for _, n in packets), "the first name server was never tried"
    # With both gone, the lookup fails and names them both.
    resolve.answers.clear()
    resolve.known.clear()
    resolve.known[""] = (float("inf"), list(ROOT_IPS))
    gone = {"org", "net"}
    try:
        resolve.resolve("example.com")
        raise AssertionError("resolved with no name server findable")
    except LookupError as e:
        assert "ns1.gone.org" in str(e) and "ns2.ok.net" in str(e), e
finally:
    resolve.ask = real_ask
    resolve.answers.clear()
    resolve.missing.clear()
    resolve.known.clear()
    resolve.known[""] = (float("inf"), list(ROOT_IPS))

# QNAME minimisation, offline: each server must be asked only for the next label down, as
# type A, and only the servers for example.com may see the whole name and its real type.
asked = []
broken_ent = False


def minimal_ask(server, name, qtype=resolve.A, timeout=3, verbose=False):
    asked.append((server, name, qtype))
    empty = {"id": 0, "rcode": 0, "truncated": False, "answers": [], "authority": [], "additional": []}
    ns = lambda zone, host: {"name": zone, "type": resolve.NS, "ttl": 3600, "value": host}
    a = lambda host, ip: {"name": host, "type": resolve.A, "ttl": 3600, "value": ip}
    if server in ROOT_IPS:
        return dict(empty, authority=[ns("com", "a.gtld")], additional=[a("a.gtld", "10.0.0.1")])
    if server == "10.0.0.1":
        return dict(empty, authority=[ns("example.com", "ns.example.com")], additional=[a("ns.example.com", "10.0.0.2")])
    # example.com's own servers: everything under it is theirs, with no further zone cut.
    if name.count(".") < 5 and name != "www.shop.example.com" and not name.startswith("a."):
        # An empty name on the way down: NOERROR with no records, unless this server is the
        # kind that wrongly says the name does not exist.
        return dict(empty, rcode=3 if broken_ent else 0)
    return dict(empty, answers=[{"name": name, "type": qtype, "ttl": 60, "value": "2001:db8::1"}])


def fresh():
    asked.clear()
    resolve.answers.clear()
    resolve.missing.clear()
    resolve.known.clear()
    resolve.known[""] = (float("inf"), list(ROOT_IPS))


resolve.ask = minimal_ask
try:
    fresh()
    assert resolve.resolve("www.shop.example.com", resolve.AAAA)[0]["value"] == "2001:db8::1"
    names = [(name, qtype) for _, name, qtype in asked]
    assert names == [("com", resolve.A), ("example.com", resolve.A), ("shop.example.com", resolve.A),
                     ("www.shop.example.com", resolve.AAAA)], names
    # A server that says an in-between name does not exist is asked the whole question
    # instead, and the real name is neither lost nor remembered as missing.
    fresh()
    broken_ent = True
    assert resolve.resolve("www.shop.example.com", resolve.AAAA)[0]["value"] == "2001:db8::1"
    assert "www.shop.example.com" not in resolve.missing and "shop.example.com" not in resolve.missing
    broken_ent = False
    # A long name below one zone: three in-between steps, then the whole name, as RFC 9156 caps it.
    fresh()
    resolve.resolve("a.b.c.d.e.example.com")
    below = [name for server, name, _ in asked if server == "10.0.0.2"]
    assert below == ["e.example.com", "d.e.example.com", "c.d.e.example.com", "a.b.c.d.e.example.com"], below
    # Switched off, the root sees the whole name, which is what minimisation exists to stop.
    fresh()
    resolve.MINIMISE = False
    resolve.resolve("www.shop.example.com", resolve.AAAA)
    assert asked[0][1] == "www.shop.example.com", asked
finally:
    resolve.MINIMISE = True
    resolve.ask = real_ask
    fresh()

# EDNS, offline, against a real UDP socket on this machine. The handler is a server: it
# gets the query's bytes and returns the reply's. Nothing listens for TCP.
def serve(handler):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    seen = []

    def loop():
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                return
            seen.append(data)
            sock.sendto(handler(data), addr)

    threading.Thread(target=loop, daemon=True).start()
    return sock, seen


def reply_to(query, rcode=0, answers=b"", count=0, ident=None):
    question_end = query.index(b"\0", 12) + 5
    ident = struct.unpack("!H", query[:2])[0] if ident is None else ident
    return struct.pack("!HHHHHH", ident, 0x8400 | rcode, 1, count, 0, 0) + query[12:question_end] + answers


has_opt = lambda query: query[10:12] == b"\0\1"
OPT_RECORD = b"\0" + struct.pack("!HHIH", resolve.OPT, 1232, 0, 0)
# 804 bytes of TXT: too big for plain UDP's 512, well inside EDNS's 1232.
big_txt = b"\xc0\x0c" + struct.pack("!HHIH", resolve.TXT, 1, 60, 804) + (b"\xc8" + b"x" * 200) * 4
small_a = b"\xc0\x0c" + struct.pack("!HHIH", resolve.A, 1, 60, 4) + bytes([10, 1, 2, 3])

# A modern server sends the big answer over UDP when asked with EDNS, so TCP is never needed.
sock, seen = serve(lambda q: reply_to(q, answers=big_txt, count=1) if has_opt(q) else reply_to(q))
try:
    got = resolve.ask("127.0.0.1", "example.com", resolve.TXT, timeout=2, port=sock.getsockname()[1])
    assert not got["truncated"] and len(got["answers"]) == 1 and "x" * 200 in got["answers"][0]["value"]
    assert len(seen) == 1 and seen[0].endswith(OPT_RECORD), seen
finally:
    sock.close()

# An old server calls the OPT record a format error. The question is asked again without it.
sock, seen = serve(lambda q: reply_to(q, rcode=resolve.FORMERR) if has_opt(q) else reply_to(q, answers=small_a, count=1))
try:
    got = resolve.ask("127.0.0.1", "example.com", timeout=2, port=sock.getsockname()[1])
    assert got["answers"][0]["value"] == "10.1.2.3", got
    assert len(seen) == 2 and has_opt(seen[0]) and not has_opt(seen[1]), seen
finally:
    sock.close()

# A FORMERR with the wrong id is a forgery, and must not talk the resolver out of EDNS.
sock, seen = serve(lambda q: reply_to(q, rcode=resolve.FORMERR, ident=(struct.unpack("!H", q[:2])[0] + 1) % 65536))
try:
    resolve.ask("127.0.0.1", "example.com", timeout=2, port=sock.getsockname()[1])
    raise AssertionError("believed a reply with the wrong id")
except ValueError:
    assert len(seen) == 1, seen
finally:
    sock.close()

# Live: a.root-servers.net has had the same address since 1997, so both resolvers must agree.
ours = {r["value"] for r in resolve.resolve("a.root-servers.net")}
theirs = {ai[4][0] for ai in socket.getaddrinfo("a.root-servers.net", 53, socket.AF_INET)}
assert ours == theirs == {"198.41.0.4"}, (ours, theirs)
print("ok")
