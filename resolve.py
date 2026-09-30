# A DNS resolver that starts at the root servers and follows referrals itself.
# Run: python resolve.py example.com   (add -v to see every hop). DOCS.md explains the format.
import math
import random
import socket
import struct
import sys
import time

ROOTS = {"a": "198.41.0.4", "b": "170.247.170.2", "c": "192.33.4.12", "d": "199.7.91.13", "e": "192.203.230.10",
         "f": "192.5.5.241", "g": "192.112.36.4", "h": "198.97.190.53", "i": "192.36.148.17", "j": "192.58.128.30",
         "k": "193.0.14.129", "l": "199.7.83.42", "m": "202.12.27.33"}
A, NS, CNAME, MX, TXT, AAAA = 1, 2, 5, 15, 16, 28
TYPE_NAMES = {A: "A", NS: "NS", CNAME: "CNAME", AAAA: "AAAA", 6: "SOA", MX: "MX", TXT: "TXT"}
# Referrals seen so far, zone -> name server addresses, so a second lookup need not start at the root.
# Referrals seen so far, zone -> (expiry, name server addresses), so a later lookup can start
# below the root. The root never expires. Answers are kept the same way, until their TTL is up.
known = {"": (math.inf, list(ROOTS.values()))}
answers = {}
clock = time.monotonic  # a test swaps this to jump forward without waiting


def build_query(name, qtype=A):
    header = struct.pack("!HHHHHH", random.randrange(65536), 0, 1, 0, 0, 0)  # id, flags (no RD: we recurse), 1 question
    qname = b"".join(bytes([len(label)]) + label.encode() for label in name.rstrip(".").split(".")) + b"\0"
    return header + qname + struct.pack("!HH", qtype, 1)


def read_name(data, pos):
    # Labels, or a two-byte pointer (top bits 11) to an earlier name. A pointer ends the name.
    labels, jumped, end = [], False, None
    while True:
        length = data[pos]
        if length & 0xC0 == 0xC0:
            if not jumped: end = pos + 2
            pos = struct.unpack("!H", data[pos:pos + 2])[0] & 0x3FFF
            jumped = True
            continue
        pos += 1
        if length == 0: break
        labels.append(data[pos:pos + length].decode("ascii"))
        pos += length
    return ".".join(labels), end if jumped else pos


def read_record(data, pos):
    name, pos = read_name(data, pos)
    rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
    pos += 10
    rdata = data[pos:pos + rdlen]
    if rtype in (NS, CNAME): value = read_name(data, pos)[0]
    elif rtype == A: value = ".".join(str(b) for b in rdata)
    elif rtype == AAAA: value = socket.inet_ntop(socket.AF_INET6, rdata)
    elif rtype == MX: value = f"{struct.unpack('!H', rdata[:2])[0]} {read_name(data, pos + 2)[0]}"
    elif rtype == TXT: value = " ".join(repr(rdata[i + 1:i + 1 + rdata[i]].decode("utf-8", "replace")) for i in _txt_offsets(rdata))
    else: value = rdata
    return {"name": name, "type": rtype, "ttl": ttl, "value": value}, pos + rdlen


def _txt_offsets(rdata):
    # TXT data is a run of length-prefixed strings.
    i = 0
    while i < len(rdata):
        yield i
        i += 1 + rdata[i]


def parse(data):
    ident, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    pos = 12
    for _ in range(qd):
        _, pos = read_name(data, pos)
        pos += 4
    sections = []
    for count in (an, ns, ar):
        records = []
        for _ in range(count):
            record, pos = read_record(data, pos)
            records.append(record)
        sections.append(records)
    return {"id": ident, "rcode": flags & 0xF, "truncated": bool(flags & 0x200), "answers": sections[0], "authority": sections[1], "additional": sections[2]}


def ask(server, name, qtype=A, timeout=3, verbose=False):
    query = build_query(name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, (server, 53))
        data, _ = sock.recvfrom(4096)
    reply = parse(data)
    if reply["truncated"]:
        # Without EDNS a UDP reply stops at 512 bytes; the same query over TCP gets the whole thing.
        if verbose: print(f"  {server} truncated the reply at {len(data)} bytes, asking again over TCP")
        with socket.create_connection((server, 53), timeout=timeout) as sock:
            sock.sendall(struct.pack("!H", len(query)) + query)
            length = struct.unpack("!H", _read_exactly(sock, 2))[0]
            data = _read_exactly(sock, length)
        reply = parse(data)
    if reply["id"] != struct.unpack("!H", query[:2])[0]: raise ValueError("reply id does not match the query")
    return reply


def _read_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk: raise ConnectionError("server closed the TCP connection early")
        buf += chunk
    return buf


def remember_answer(key, records):
    answers[key] = (clock() + min(r["ttl"] for r in records), records)
    return records


def resolve(name, qtype=A, verbose=False, depth=0):
    if depth > 8: raise RuntimeError("too many CNAME or referral hops")
    name = name.rstrip(".").lower()
    now = clock()
    key = (name, qtype)
    if key in answers and answers[key][0] > now:
        expires, records = answers[key]
        if verbose: print(f"  {name} {TYPE_NAMES.get(qtype, qtype)} from the cache, {int(expires - now)}s left")
        # A cached answer shows the time it has left, as a real resolver's does.
        return [dict(r, ttl=int(expires - now)) for r in records]
    # Start from the closest zone still in date: "" (the root) at worst.
    live = [z for z, (expires, _) in known.items() if expires > now]
    zone = next(z for z in sorted(live, key=len, reverse=True) if name == z or name.endswith("." + z) or z == "")
    servers = known[zone][1]
    while True:
        server = random.choice(servers)
        reply = ask(server, name, qtype, verbose=verbose)
        if verbose: print(f"  {server:<16} {name} {TYPE_NAMES.get(qtype, qtype)} -> {len(reply['answers'])} answers, {len(reply['authority'])} authority, {len(reply['additional'])} glue")
        if reply["rcode"] == 3: raise LookupError(f"{name} does not exist (NXDOMAIN)")
        wanted = [r for r in reply["answers"] if r["type"] == qtype]
        if wanted: return remember_answer(key, wanted)
        cname = next((r for r in reply["answers"] if r["type"] == CNAME), None)
        if cname:
            if verbose: print(f"  {name} is an alias for {cname['value']}")
            target = resolve(cname["value"], qtype, verbose, depth + 1)
            # The alias is only good for as long as both it and what it points at are.
            return remember_answer(key, [dict(r, ttl=min(r["ttl"], cname["ttl"])) for r in target])
        referral = [r for r in reply["authority"] if r["type"] == NS]
        if not referral: raise LookupError(f"{server} had no answer and no referral for {name}")
        ns_names = [r["value"] for r in referral]
        zone = referral[0]["name"]
        # Glue: the referral usually carries the name servers' addresses so we need not look them up.
        glue = [r["value"] for r in reply["additional"] if r["type"] == A and r["name"] in ns_names]
        if glue: servers = glue
        else:
            if verbose: print(f"  no glue for {ns_names[0]}, resolving it first")
            servers = [r["value"] for r in resolve(ns_names[0], A, verbose, depth + 1)]
        known[zone] = (clock() + min(r["ttl"] for r in referral), servers)

if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if not args: sys.exit("usage: python resolve.py NAME [A|AAAA|NS|MX|TXT] [-v]")
    qtype = {v: k for k, v in TYPE_NAMES.items()}.get(args[1].upper() if len(args) > 1 else "A", A)
    try:
        for r in resolve(args[0], qtype, verbose="-v" in sys.argv):
            print(f"{r['name']}\t{r['ttl']}\t{TYPE_NAMES.get(r['type'], r['type'])}\t{r['value']}")
    except (LookupError, RuntimeError, socket.timeout) as e:
        sys.exit(f"resolve: {e}")
