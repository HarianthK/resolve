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

# Live: a.root-servers.net has had the same address since 1997, so both resolvers must agree.
ours = {r["value"] for r in resolve.resolve("a.root-servers.net")}
theirs = {ai[4][0] for ai in socket.getaddrinfo("a.root-servers.net", 53, socket.AF_INET)}
assert ours == theirs == {"198.41.0.4"}, (ours, theirs)
print("ok")
