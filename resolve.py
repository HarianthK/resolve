# A DNS resolver that starts at the root servers and follows referrals itself.
# Run: python resolve.py example.com   (add -v to see every hop). DOCS.md explains the format.
import base64
import ipaddress
import math
import random
import socket
import socketserver
import struct
import sys
import threading
import time

ROOTS = {"a": "198.41.0.4", "b": "170.247.170.2", "c": "192.33.4.12", "d": "199.7.91.13", "e": "192.203.230.10",
         "f": "192.5.5.241", "g": "192.112.36.4", "h": "198.97.190.53", "i": "192.36.148.17", "j": "192.58.128.30",
         "k": "193.0.14.129", "l": "199.7.83.42", "m": "202.12.27.33"}
A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, OPT, DS, RRSIG, NSEC, DNSKEY, NSEC3, CAA = 1, 2, 5, 6, 12, 15, 16, 28, 33, 41, 43, 46, 47, 48, 50, 257
TYPE_NAMES = {A: "A", NS: "NS", CNAME: "CNAME", AAAA: "AAAA", SOA: "SOA", PTR: "PTR", MX: "MX", TXT: "TXT", SRV: "SRV", DS: "DS", RRSIG: "RRSIG", NSEC: "NSEC", DNSKEY: "DNSKEY", NSEC3: "NSEC3", CAA: "CAA"}
FORMERR = 1
# The UDP reply size EDNS asks for: DNS Flag Day 2020's figure, small enough never to fragment.
EDNS_SIZE = 1232
# Referrals seen so far, zone -> (expiry, name server addresses), so a later lookup can start
# below the root. The root never expires. Answers are kept the same way, until their TTL is up.
known = {"": (math.inf, list(ROOTS.values()))}
answers = {}
# RFC 4035's DO bit: set, servers send the RRSIG records that sign each answer. dnssec.py sets it.
DNSSEC_OK = False
# Names a server said do not exist, name -> (expiry, the reply's authority section, its SOA and
# proof). A missing name is missing for every type.
missing = {}
clock = time.monotonic  # a test swaps this to jump forward without waiting
# RFC 9156: tell each server only the next label down, not the whole name. DOCS.md has why.
MINIMISE = True
# RFC 8767: when no server answers, an expired answer up to a day old is better than none,
# handed out with a 30 second TTL so callers come back soon.
STALE_FOR, STALE_TTL = 86400, 30


class Unreachable(LookupError):
    """No server for the name answered at all, as opposed to answering that it does not exist."""


class NoData(LookupError):
    """No records of the type asked, or no such name; authority holds the reply's proof."""
    def __init__(self, message, authority, rcode=0):
        super().__init__(message)
        self.authority, self.rcode = authority, rcode


def type_bitmap(data):
    # NSEC and NSEC3 list the types a name has as bitmaps: a window number, a length, then bits.
    types, i = set(), 0
    while i + 2 <= len(data):
        window, length = data[i], data[i + 1]
        for j, byte in enumerate(data[i + 2:i + 2 + length]):
            types.update(window * 256 + j * 8 + bit for bit in range(8) if byte & (0x80 >> bit))
        i += 2 + length
    return types


def build_query(name, qtype=A, edns=True):
    # id, flags (no RD: we recurse), 1 question, and with EDNS one extra record
    header = struct.pack("!HHHHHH", random.randrange(65536), 0, 1, 0, 0, 1 if edns else 0)
    qname = name_wire(name)  # the root is the empty name: one zero byte, nothing before it
    # The OPT pseudo-record: no name, and its class field is the UDP size we can take.
    opt = b"\0" + struct.pack("!HHIH", OPT, EDNS_SIZE, 0x8000 if DNSSEC_OK else 0, 0) if edns else b""
    return header + qname + struct.pack("!HH", qtype, 1) + opt


def name_wire(name):
    # A name as uncompressed lower-case labels, the canonical form signatures are made over.
    return b"".join(bytes([len(label)]) + label.lower().encode() for label in name.split(".") if label) + b"\0"


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
    rdata = wire = data[pos:pos + rdlen]
    # wire is the record data in canonical form (RFC 4034 section 6.2): any names in it spelled out.
    if rtype in (NS, CNAME, PTR): value = read_name(data, pos)[0]; wire = name_wire(value)
    elif rtype == A: value = ".".join(str(b) for b in rdata)
    elif rtype == AAAA: value = socket.inet_ntop(socket.AF_INET6, rdata)
    elif rtype == MX: value = f"{struct.unpack('!H', rdata[:2])[0]} {read_name(data, pos + 2)[0]}"; wire = rdata[:2] + name_wire(value.split()[1])
    # SRV (RFC 2782): priority, weight and port, then the host the service runs on.
    # CAA (RFC 8659): a flags byte, a tag such as issue, then which certificate authority it names.
    elif rtype == CAA: value = f'{rdata[0]} {rdata[2:2 + rdata[1]].decode("ascii", "replace")} "{rdata[2 + rdata[1]:].decode("utf-8", "replace")}"'
    # DNSSEC, shown but not checked: a key is flags, protocol, algorithm and the key itself; a DS is
    # the parent's fingerprint of a child's key: its tag, algorithm, digest type and digest.
    elif rtype == DNSKEY: value = "{} {} {} ".format(*struct.unpack("!HBB", rdata[:4])) + base64.b64encode(rdata[4:]).decode()
    elif rtype == DS: value = "{} {} {} ".format(*struct.unpack("!HBB", rdata[:4])) + rdata[4:].hex().upper()
    elif rtype == SRV: value = "{} {} {} ".format(*struct.unpack("!HHH", rdata[:6])) + read_name(data, pos + 6)[0]; wire = rdata[:6] + name_wire(value.split()[3])
    elif rtype == TXT: value = " ".join(repr(rdata[i + 1:i + 1 + rdata[i]].decode("utf-8", "replace")) for i in _txt_offsets(rdata))
    elif rtype == SOA:
        # Two names, then five numbers; the last says how long a "does not exist" may be kept.
        primary, at = read_name(data, pos)
        mailbox, at = read_name(data, at)
        serial, refresh, retry, expire, minimum = struct.unpack("!IIIII", data[at:at + 20])
        value = f"{primary} {mailbox} {serial} {refresh} {retry} {expire} {minimum}"
        wire = name_wire(primary) + name_wire(mailbox) + data[at:at + 20]
        return {"name": name, "type": rtype, "ttl": ttl, "value": value, "minimum": minimum, "wire": wire}, pos + rdlen
    elif rtype == NSEC:
        # The next name that exists in the zone, and every type this name has (RFC 4034 section 4).
        following, at = read_name(data, pos)
        value = {"next": following.lower(), "types": type_bitmap(data[at:pos + rdlen])}
    elif rtype == NSEC3:
        # The same, with names hashed (RFC 5155): how, the flags (1 is opt-out), and the next hash.
        alg, flags, iterations, salt_len = struct.unpack("!BBHB", rdata[:5])
        salt = rdata[5:5 + salt_len]
        hash_len = rdata[5 + salt_len]
        following = rdata[6 + salt_len:6 + salt_len + hash_len]
        value = {"algorithm": alg, "flags": flags, "iterations": iterations, "salt": salt, "next": following,
                 "types": type_bitmap(rdata[6 + salt_len + hash_len:])}
    elif rtype == RRSIG:
        # A signature over one type of record at this name: who signed, with which key, valid when.
        covered, alg, labels, original_ttl, expiration, inception, key_tag = struct.unpack("!HBBIIIH", rdata[:18])
        signer, at = read_name(data, pos + 18)
        sig = dict(covered=covered, algorithm=alg, labels=labels, original_ttl=original_ttl, expiration=expiration,
                   inception=inception, key_tag=key_tag, signer=signer.lower(), signature=data[at:pos + rdlen])
        value = f"{TYPE_NAMES.get(covered, covered)} {alg} {labels} {original_ttl} {expiration} {inception} {key_tag} {signer}. " + base64.b64encode(sig["signature"]).decode()
        return {"name": name, "type": rtype, "ttl": ttl, "value": value, "rrsig": sig, "wire": rdata}, pos + rdlen
    else: value = rdata
    return {"name": name, "type": rtype, "ttl": ttl, "value": value, "wire": wire}, pos + rdlen


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


def ask(server, name, qtype=A, timeout=3, verbose=False, port=53, edns=True):
    query = build_query(name, qtype, edns)
    ident = struct.unpack("!H", query[:2])[0]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(query, (server, port))
        data, _ = sock.recvfrom(4096)
    reply = parse(data)
    # Checked before anything is acted on, so a forged FORMERR cannot talk us out of EDNS.
    if reply["id"] != ident: raise ValueError("reply id does not match the query")
    if edns and reply["rcode"] == FORMERR:
        # A server too old for EDNS calls the OPT record a format error; ask it the 1987 way.
        if verbose: print(f"  {server} does not speak EDNS, asking again without it")
        return ask(server, name, qtype, timeout, verbose, port, edns=False)
    if reply["truncated"]:
        # Still too big for UDP (512 bytes without EDNS); the same query over TCP gets the whole thing.
        if verbose: print(f"  {server} truncated the reply at {len(data)} bytes, asking again over TCP")
        with socket.create_connection((server, port), timeout=timeout) as sock:
            sock.sendall(struct.pack("!H", len(query)) + query)
            length = struct.unpack("!H", _read_exactly(sock, 2))[0]
            data = _read_exactly(sock, length)
        reply = parse(data)
        if reply["id"] != ident: raise ValueError("reply id does not match the query")
    return reply


def _read_exactly(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk: raise ConnectionError("server closed the TCP connection early")
        buf += chunk
    return buf


def ask_any(servers, name, qtype, verbose):
    # One dead or lame server is common, so each of the zone's servers gets a turn before giving up.
    for server in random.sample(servers, len(servers)):
        try: return server, ask(server, name, qtype, verbose=verbose)
        except (OSError, ValueError) as e:
            if verbose: print(f"  {server:<16} did not answer ({e or type(e).__name__}), trying another")
    raise Unreachable(f"none of the {len(servers)} servers asked about {name} answered")


def addresses_of(ns_names, verbose, depth):
    # A referral without glue names its servers but not where they are. Any one will do, so
    # each is looked up in turn: one name that no longer exists must not sink the lookup.
    for host in ns_names:
        if verbose: print(f"  no glue for {host}, resolving it first")
        try:
            return [r["value"] for r in resolve(host, A, verbose, depth + 1)]
        except (LookupError, RuntimeError) as e:
            if verbose: print(f"  {host} could not be found ({e}), trying the next")
    raise LookupError(f"none of the name servers could be found: {', '.join(ns_names)}")


def next_name(name, zone, extra):
    # The name `extra` labels below zone on the way to name, or name itself once that is reached.
    labels = name.split(".")
    keep = (0 if zone == "" else len(zone.split("."))) + extra
    return ".".join(labels[-keep:]) if keep < len(labels) else name


def under(name, zone):
    return zone == "" or name == zone or name.endswith("." + zone)


def remember_answer(key, records):
    answers[key] = (clock() + min(r["ttl"] for r in records), records)
    return records


def resolve(name, qtype=A, verbose=False, depth=0, aliases=()):
    try:
        return resolve_fresh(name, qtype, verbose, depth, aliases)
    except Unreachable:
        expires, records = answers.get((name.rstrip(".").lower(), qtype), (-math.inf, None))
        if clock() - expires > STALE_FOR: raise
        if verbose: print(f"  no server answered; serving {name} from an answer expired {int(clock() - expires)}s ago")
        return [dict(r, ttl=STALE_TTL) for r in records]


def resolve_fresh(name, qtype=A, verbose=False, depth=0, aliases=()):
    if depth > 8: raise RuntimeError("too many CNAME or referral hops")
    name = name.rstrip(".").lower()
    # aliases holds the names that led here by CNAME, so a chain that comes back is named, not chased.
    if name in aliases:
        raise LookupError("CNAME loop: " + " -> ".join(aliases[aliases.index(name):] + (name,)))
    now = clock()
    expires, authority = missing.get(name, (0, []))
    if expires > now:
        if verbose: print(f"  {name} does not exist, from the cache, {int(expires - now)}s left")
        # The SOA goes with the miss, counting down like any cached record, so a client can cache it too.
        raise NoData(f"{name} does not exist (NXDOMAIN, cached)", [dict(r, ttl=int(expires - now)) for r in authority], 3)
    key = (name, qtype)
    if key in answers and answers[key][0] > now:
        expires, records = answers[key]
        if verbose: print(f"  {name} {TYPE_NAMES.get(qtype, qtype)} from the cache, {int(expires - now)}s left")
        # A cached answer shows the time it has left, as a real resolver's does.
        return [dict(r, ttl=int(expires - now)) for r in records]
    # Start from the closest zone still in date: "" (the root) at worst.
    live = [z for z, (expires, _) in known.items() if expires > now]
    # A DS record lives in the parent zone, so its question must never start at the zone itself.
    zone = next(z for z in sorted(live, key=len, reverse=True) if under(name, z) and not (qtype == DS and z == name))
    servers = known[zone][1]
    extra = 1
    while True:
        # Three in-between names with no zone cut is enough; past that the whole name goes, as the RFC caps it.
        asked = next_name(name, zone, extra) if MINIMISE and extra <= 3 else name
        asked_type = qtype if asked == name else A
        server, reply = ask_any(servers, asked, asked_type, verbose)
        if verbose: print(f"  {server:<16} {asked} {TYPE_NAMES.get(asked_type, asked_type)} -> {len(reply['answers'])} answers, {len(reply['authority'])} authority, {len(reply['additional'])} glue")
        if asked != name:
            cut = any(r["type"] == NS and r["name"].lower() != zone for r in reply["authority"])
            if reply["rcode"] == 0 and not cut:
                extra += 1  # no zone starts here, so the same servers answer for the next label too
                continue
            if reply["rcode"] != 0:
                # An odd answer to an in-between name, NXDOMAIN included, is settled by the whole question.
                extra = 4
                continue
        if reply["rcode"] == 3:
            # RFC 2308: the zone's SOA comes back with the answer, and the shorter of its own
            # TTL and its minimum field is how long the name may be remembered as missing.
            soa = next((r for r in reply["authority"] if r["type"] == SOA), None)
            if soa: missing[name] = (clock() + min(soa["ttl"], soa["minimum"]), reply["authority"])
            raise NoData(f"{name} does not exist (NXDOMAIN)", reply["authority"], 3)
        # Only records about the name asked are believed; anything else in the reply could be planted.
        about = [r for r in reply["answers"] if r["name"].lower() == name]
        wanted = [r for r in about if r["type"] == qtype]
        # With the DO bit set, the signatures over the answer come back alongside it.
        # A wildcard's answer comes with the NSEC or NSEC3 proving no closer name exists, so that is kept too.
        proof = [r for r in reply["authority"] if r["type"] in (NSEC, NSEC3) or r["type"] == RRSIG and r["rrsig"]["covered"] in (NSEC, NSEC3)]
        if wanted: return remember_answer(key, wanted + [r for r in about if r["type"] == RRSIG and r["rrsig"]["covered"] == qtype] + proof)
        cname = next((r for r in about if r["type"] == CNAME), None)
        if cname:
            if verbose: print(f"  {name} is an alias for {cname['value']}")
            target = resolve(cname["value"], qtype, verbose, depth + 1, aliases + (name,))
            # The alias is only good for as long as both it and what it points at are.
            return remember_answer(key, [dict(r, ttl=min(r["ttl"], cname["ttl"])) for r in target])
        referral = [r for r in reply["authority"] if r["type"] == NS]
        if not referral: raise NoData(f"{server} had no answer and no referral for {name}", reply["authority"], reply["rcode"])
        below = referral[0]["name"].lower()
        # Bailiwick: a server may only hand down a zone between its own and the name, never sideways or up.
        if below == zone or not under(below, zone) or not under(name, below):
            raise LookupError(f"{server} referred {name} to {below or 'the root'}, outside {zone or 'the root'}")
        ns_names = [r["value"] for r in referral if r["name"].lower() == below]
        # Glue: the referral usually carries the name servers' addresses, believed only inside the server's zone.
        glue = [r["value"] for r in reply["additional"] if r["type"] == A and r["name"] in ns_names and under(r["name"].lower(), zone)]
        zone, extra = below, 1
        servers = glue or addresses_of(ns_names, verbose, depth)
        known[zone] = (clock() + min(r["ttl"] for r in referral), servers)


def record_wire(r):
    return name_wire(r["name"]) + struct.pack("!HHIH", r["type"], 1, r["ttl"], len(r["wire"])) + r["wire"]


def respond(query, udp=True, verbose=False):
    # One client question answered by recursion, as the reply bytes; None for a packet to ignore.
    if len(query) < 12: return None
    ident, flags, qd, _, _, ar = struct.unpack("!HHHHHH", query[:12])
    if flags & 0x8000: return None  # a reply, not a question: answering it could start a loop
    header = lambda rcode, counts=(0, 0, 0, 0): struct.pack("!HHHHHH", ident, 0x8080 | flags & 0x7900 | rcode, *counts)
    if flags & 0x7800 or qd != 1: return header(4)  # NOTIMP: only plain queries, one question each
    try:
        name, pos = read_name(query, 12)
        qtype = struct.unpack("!H", query[pos:pos + 2])[0]
        question = query[12:pos + 4]
    except (IndexError, UnicodeDecodeError, struct.error):
        return header(FORMERR)
    # A client that sends an OPT record says how big a UDP reply it takes; without one, 512.
    opt = query[pos + 4:pos + 9]
    edns = ar and opt[:3] == b"\0\0" + bytes([OPT]) and len(opt) == 5
    limit = max(512, struct.unpack("!H", opt[3:])[0]) if edns else 512
    rcode, answer, authority = 0, [], []
    try:
        answer = resolve(name, qtype, verbose)
    except NoData as e:
        rcode, authority = (e.rcode, [r for r in e.authority if r["type"] == SOA]) if e.rcode in (0, 3) else (2, [])
    except (LookupError, RuntimeError, OSError, ValueError):
        rcode = 2  # SERVFAIL: no server answered, or none could be believed
    # resolve follows aliases and returns only the target's records, so one CNAME stands for the chain.
    if answer and answer[0]["name"].lower() != name.rstrip(".").lower():
        answer = [{"name": name, "type": CNAME, "ttl": min(r["ttl"] for r in answer), "wire": name_wire(answer[0]["name"])}] + answer
    if verbose: print(f"{name} {TYPE_NAMES.get(qtype, qtype)} -> rcode {rcode}, {len(answer)} answers")
    tail = b"\0" + struct.pack("!HHIH", OPT, EDNS_SIZE, 0, 0) if edns else b""
    reply = header(rcode, (1, len(answer), len(authority), 1 if edns else 0)) + question + b"".join(map(record_wire, answer + authority)) + tail
    if udp and len(reply) > limit:
        # Too big: the question alone with TC set, and the client asks again over TCP.
        reply = header(rcode | 0x200, (1, 0, 0, 1 if edns else 0)) + question + tail
    return reply


class _UDP(socketserver.BaseRequestHandler):
    def handle(self):
        query, sock = self.request
        with self.server.lock: reply = respond(query, True, self.server.verbose)
        if reply: sock.sendto(reply, self.client_address)


class _TCP(socketserver.BaseRequestHandler):
    def handle(self):
        # Over TCP each message has a two-byte length in front, and one connection can carry several.
        try:
            while True:
                query = _read_exactly(self.request, struct.unpack("!H", _read_exactly(self.request, 2))[0])
                with self.server.lock: reply = respond(query, False, self.server.verbose)
                if reply: self.request.sendall(struct.pack("!H", len(reply)) + reply)
        except (ConnectionError, OSError):
            pass


def serve(port=5300, host="127.0.0.1", verbose=False):
    # A recursive server on UDP and TCP, localhost only, since an open resolver gets abused.
    # ponytail: one lock, one lookup at a time; per-name locks if many clients ever share it.
    udp = socketserver.ThreadingUDPServer((host, port), _UDP)
    tcp = socketserver.ThreadingTCPServer((host, udp.server_address[1]), _TCP)
    lock = threading.Lock()
    for s in (udp, tcp):
        s.lock, s.verbose, s.daemon_threads = lock, verbose, True
        threading.Thread(target=s.serve_forever, daemon=True).start()
    return udp, tcp


if __name__ == "__main__":
    if "--serve" in sys.argv:
        port = int(next((a for a in sys.argv[1:] if a.isdigit()), 5300))
        serve(port, verbose="-v" in sys.argv)
        print(f"answering DNS on 127.0.0.1 port {port}, UDP and TCP; try: dig @127.0.0.1 -p {port} example.com")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            sys.exit()
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if not args: sys.exit("usage: python resolve.py NAME [A|AAAA|NS|MX|TXT|SRV|PTR|CAA|DS|DNSKEY] [-v] [--dnssec], or -x ADDRESS, or --serve [PORT]")
    qtype = {v: k for k, v in TYPE_NAMES.items()}.get(args[1].upper() if len(args) > 1 else "A", A)
    if "-x" in sys.argv:
        # A reverse lookup is a PTR question about the address written backwards under in-addr.arpa or ip6.arpa.
        try: args[0], qtype = ipaddress.ip_address(args[0]).reverse_pointer, PTR
        except ValueError: sys.exit(f"resolve: {args[0]} is not an IPv4 or IPv6 address")
    if "--dnssec" in sys.argv:
        # The answer only if its signatures chain up to the root's key; the chain is printed below it.
        import dnssec
        try:
            records, chain = dnssec.validate(args[0], qtype)
        except dnssec.Insecure as e:
            sys.exit(f"resolve: insecure: {e}")
        except dnssec.Bogus as e:
            sys.exit(f"resolve: BOGUS, not using the answer: {e}")
        except (LookupError, RuntimeError, socket.timeout) as e:
            sys.exit(f"resolve: {e}")
        for r in records:
            print(f"{r['name']}\t{r['ttl']}\t{TYPE_NAMES.get(r['type'], r['type'])}\t{r['value']}")
        print("; secure: " + "\n;   ".join(chain))
        sys.exit()
    try:
        for r in resolve(args[0], qtype, verbose="-v" in sys.argv):
            print(f"{r['name']}\t{r['ttl']}\t{TYPE_NAMES.get(r['type'], r['type'])}\t{r['value']}")
    except (LookupError, RuntimeError, socket.timeout) as e:
        sys.exit(f"resolve: {e}")
