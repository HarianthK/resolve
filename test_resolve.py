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

# Live: a.root-servers.net has had the same address since 1997, so both resolvers must agree.
ours = {r["value"] for r in resolve.resolve("a.root-servers.net")}
theirs = {ai[4][0] for ai in socket.getaddrinfo("a.root-servers.net", 53, socket.AF_INET)}
assert ours == theirs == {"198.41.0.4"}, (ours, theirs)
print("ok")
