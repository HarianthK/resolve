# DNSSEC validation: an answer is believed only if its signature chains up to the root zone's key.
# Run: python resolve.py cloudflare.com --dnssec. DOCS.md, "Checking the signatures", has the steps.
import base64
import hashlib
import struct
import time

import resolve

# The root's key-signing keys as IANA publishes them (root-anchors.xml), KSK-2017 and KSK-2024:
# (key tag, algorithm, digest type) -> SHA-256 of the key. Everything else is checked against these.
ANCHORS = {(20326, 8, 2): bytes.fromhex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
           (38696, 8, 2): bytes.fromhex("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16")}
ALGORITHMS = {8: "RSA/SHA-256", 10: "RSA/SHA-512", 13: "ECDSA P-256/SHA-256", 15: "Ed25519"}

# NIST P-256: y^2 = x^3 - 3x + b over the integers mod P, with base point G of prime order N.
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
# PKCS #1 v1.5 puts the hash inside this DER prefix, which names the hash function.
DIGEST_INFO = {"sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
               "sha512": bytes.fromhex("3051300d060960864801650304020305000440")}


class Bogus(Exception):
    """The answer claims to be signed, but the signatures do not hold up: do not use it."""


class Insecure(Exception):
    """Nothing says this answer should be signed, so it can be neither trusted nor called forged."""


def on_curve(point):
    x, y = point
    return 0 <= x < P and 0 <= y < P and (y * y - x * x * x + 3 * x - B) % P == 0


def add(p1, p2):
    # Adding points on the curve; None is the point at infinity, the identity.
    if p1 is None or p2 is None:
        return p1 or p2
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    slope = (3 * x1 * x1 - 3) * pow(2 * y1, -1, P) if p1 == p2 else (y2 - y1) * pow(x2 - x1, -1, P)
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def times(k, point):
    # k copies of point added up, by doubling and adding along k's bits.
    total = None
    while k:
        if k & 1:
            total = add(total, point)
        point, k = add(point, point), k >> 1
    return total


def ecdsa_ok(key, signature, data):
    # RFC 6605: the key is x then y, the signature r then s, 32 bytes each.
    if len(key) != 64 or len(signature) != 64:
        return False
    q = (int.from_bytes(key[:32], "big"), int.from_bytes(key[32:], "big"))
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    if not on_curve(q) or not (0 < r < N and 0 < s < N):
        return False
    e, w = int.from_bytes(hashlib.sha256(data).digest(), "big"), pow(s, -1, N)
    point = add(times(e * w % N, G), times(r * w % N, q))
    return point is not None and point[0] % N == r


# Ed25519 (RFC 8032): the twisted Edwards curve -x^2 + y^2 = 1 + d x^2 y^2 over the integers mod
# 2^255 - 19, whose base point has prime order L. Its addition law has no special cases.
EP = 2 ** 255 - 19
ED = -121665 * pow(121666, -1, EP) % EP
EL = 2 ** 252 + 27742317777372353535851937790883648493


def ed_add(p1, p2):
    (x1, y1), (x2, y2) = p1, p2
    t = ED * x1 * x2 * y1 * y2 % EP
    return (x1 * y2 + x2 * y1) * pow(1 + t, -1, EP) % EP, (y1 * y2 + x1 * x2) * pow(1 - t, -1, EP) % EP


def ed_times(k, point):
    total = (0, 1)  # the identity
    while k:
        if k & 1:
            total = ed_add(total, point)
        point, k = ed_add(point, point), k >> 1
    return total


def ed_decode(data):
    # A point is y in little-endian with x's low bit on top; x comes back from the curve equation.
    if len(data) != 32:
        return None
    n = int.from_bytes(data, "little")
    y, sign = n & (2 ** 255 - 1), n >> 255
    if y >= EP:
        return None
    x2 = (y * y - 1) * pow(ED * y * y + 1, -1, EP) % EP
    x = pow(x2, (EP + 3) // 8, EP)
    if (x * x - x2) % EP:
        x = x * pow(2, (EP - 1) // 4, EP) % EP
    if (x * x - x2) % EP or (x == 0 and sign):
        return None
    return (EP - x if x & 1 != sign else x), y


ED_BASE = ed_decode((4 * pow(5, -1, EP) % EP).to_bytes(32, "little"))


def ed25519_ok(key, signature, data):
    # S times the base point must equal R plus h times the key, h hashing R, the key and the data.
    a, r = ed_decode(key), ed_decode(signature[:32]) if len(signature) == 64 else None
    s = int.from_bytes(signature[32:], "little")
    if a is None or r is None or s >= EL:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + key + data).digest(), "little") % EL
    return ed_times(s, ED_BASE) == ed_add(r, ed_times(h, a))


def rsa_ok(key, signature, data, hash_name):
    # RFC 3110: a length byte (or 0 and two more), the exponent, then the modulus.
    if not key:
        return False
    size, at = (key[0], 1) if key[0] else (int.from_bytes(key[1:3], "big"), 3)
    e, n = int.from_bytes(key[at:at + size], "big"), int.from_bytes(key[at + size:], "big")
    width = len(key) - at - size
    if not (e and n) or len(signature) != width:
        return False
    inner = DIGEST_INFO[hash_name] + hashlib.new(hash_name, data).digest()
    expected = b"\x00\x01" + b"\xff" * (width - 3 - len(inner)) + b"\x00" + inner
    return pow(int.from_bytes(signature, "big"), e, n).to_bytes(width, "big") == expected


def key_tag(key):
    # RFC 4034 appendix B: a 16-bit sum of the key's data, how a signature names its key.
    total = sum(b << 8 if i % 2 == 0 else b for i, b in enumerate(key["wire"]))
    return (total + (total >> 16)) & 0xFFFF


def matches_ds(key, owner, ds):
    # A DS is a hash of the child's name and key, published in the parent: SHA-256 or SHA-384.
    tag, alg, digest_type = struct.unpack("!HBB", ds["wire"][:4])
    hash_name = {2: "sha256", 4: "sha384"}.get(digest_type)
    return (hash_name is not None and tag == key_tag(key) and alg == key["wire"][3]
            and hashlib.new(hash_name, resolve.name_wire(owner) + key["wire"]).digest() == ds["wire"][4:])


def signed_data(sig, rrset):
    # RFC 4034 section 3.1.8.1: the signature's own fields, then each record in canonical form,
    # sorted by its data, with the TTL the signer saw. A wildcard answer is signed as "*.zone".
    r = sig["rrsig"]
    labels = [label for label in rrset[0]["name"].split(".") if label]
    owner = ".".join(["*"] + labels[len(labels) - r["labels"]:]) if r["labels"] < len(labels) else ".".join(labels)
    head = sig["wire"][:18] + resolve.name_wire(r["signer"])
    return head + b"".join(resolve.name_wire(owner) + struct.pack("!HHIH", r["covered"], 1, r["original_ttl"], len(w)) + w
                           for w in sorted({rr["wire"] for rr in rrset}))


def verify(rrset, sigs, keys, zone, now):
    # Returns the key that signed rrset; raises Bogus with the reason if none did.
    if not sigs:
        raise Bogus(f"{rrset[0]['name'] or '.'} {resolve.TYPE_NAMES.get(rrset[0]['type'])} has no signature")
    reasons = []
    for sig in sigs:
        r = sig["rrsig"]
        if r["signer"] != zone or not resolve.under(rrset[0]["name"].lower(), zone):
            reasons.append(f"signed by {r['signer'] or '.'}, not {zone or '.'}")
        elif not r["inception"] <= now <= r["expiration"]:
            reasons.append(f"signature by key {r['key_tag']} is valid {r['inception']} to {r['expiration']}, not now ({now})")
        elif r["algorithm"] not in ALGORITHMS:
            raise Insecure(f"{zone or '.'} signs with algorithm {r['algorithm']}, which this does not check")
        else:
            data = signed_data(sig, rrset)
            for key in keys:
                k = key["wire"]
                if key_tag(key) != r["key_tag"] or k[3] != r["algorithm"] or not k[0] & 1:
                    continue  # flags bit 7 (the high byte's low bit) marks a zone key
                if r["algorithm"] == 13 and ecdsa_ok(k[4:], r["signature"], data):
                    return key
                if r["algorithm"] == 15 and ed25519_ok(k[4:], r["signature"], data):
                    return key
                if r["algorithm"] in (8, 10) and rsa_ok(k[4:], r["signature"], data, "sha256" if r["algorithm"] == 8 else "sha512"):
                    return key
            reasons.append(f"no key {r['key_tag']} of {zone or '.'} verifies the signature")
    raise Bogus(f"{rrset[0]['name'] or '.'} {resolve.TYPE_NAMES.get(rrset[0]['type'])}: " + "; ".join(reasons))


def lookup(name, qtype):
    # The live way to fetch an RRset and its signatures; a test passes recorded answers instead.
    resolve.DNSSEC_OK = True
    try:
        records = resolve.resolve(name, qtype)
    except resolve.NoData as e:
        records = e.authority  # no answer, but the proof that there is none, and its signatures
    except LookupError:
        return [], []
    return [r for r in records if r["type"] != resolve.RRSIG], [r for r in records if r["type"] == resolve.RRSIG]


def nsec3_hash(name, salt, iterations):
    # RFC 5155 section 5: SHA-1 of the canonical name and the salt, then again of that, iterations times.
    digest = hashlib.sha1(resolve.name_wire(name) + salt).digest()
    for _ in range(iterations):
        digest = hashlib.sha1(digest + salt).digest()
    return digest


def order(name):
    # RFC 4034 section 6.1: names sort by their labels from the right, each as lowercase bytes.
    return tuple(label.encode("latin-1") for label in reversed(name.lower().split("."))) if name else ()


def covers(owner, after, target):
    # Whether target falls strictly between a record's owner and next; the last record wraps round.
    return owner < target < after if owner < after else target > owner or target < after


def checker(zone, sigs, keys, now):
    # Returns a function that passes a record through only if zone's keys signed it.
    def checked(r):
        verify([r], [s for s in sigs if s["rrsig"]["covered"] == r["type"] and s["name"].lower() == r["name"].lower()], keys, zone, now)
        return r
    return checked


def hashed(zone, proof):
    # zone's NSEC3 records by the hash they are named for, with the salt and iterations they share.
    nsec3 = [r for r in proof if r["type"] == resolve.NSEC3 and r["name"].lower().partition(".")[2] == zone]
    if not nsec3:
        return {}, b"", 0
    alg, salt, iterations = nsec3[0]["value"]["algorithm"], nsec3[0]["value"]["salt"], nsec3[0]["value"]["iterations"]
    if alg != 1 or iterations > 150 or any((r["value"]["salt"], r["value"]["iterations"]) != (salt, iterations) for r in nsec3):
        raise Insecure(f"{zone or '.'}'s NSEC3 uses parameters this does not check (algorithm {alg}, {iterations} iterations)")
    owners = {}
    for r in nsec3:
        try:
            owners[base64.b32hexdecode(r["name"].partition(".")[0].upper())] = r
        except ValueError:
            pass
    return owners, salt, iterations


def closest_encloser(name, zone, owners, salt, iterations):
    # RFC 5155 section 7.2.1: the nearest name above name that an NSEC3 matches, its record, and
    # the record covering the hash of the name one label below it; None if the records show no such pair.
    labels = name.split(".")
    for i in range(1, len(labels) - (len(zone.split(".")) if zone else 0) + 1):
        encloser, closer = ".".join(labels[i:]), ".".join(labels[i - 1:])
        if nsec3_hash(encloser, salt, iterations) in owners:
            target = nsec3_hash(closer, salt, iterations)
            cover = next((r for owner, r in owners.items() if covers(owner, r["value"]["next"], target)), None)
            return (encloser, owners[nsec3_hash(encloser, salt, iterations)], cover) if cover else None
    return None


def proves_no_ds(zone, parent, proof, sigs, keys, now):
    # Whether signed NSEC or NSEC3 records from parent show zone is a delegation with no DS.
    # Returns how, or None. Every record used must carry parent's valid signature.
    checked = checker(parent, sigs, keys, now)
    delegation = lambda types: resolve.NS in types and resolve.DS not in types and resolve.SOA not in types
    for r in proof:
        if r["type"] == resolve.NSEC and r["name"].lower() == zone:
            return "NSEC" if delegation(checked(r)["value"]["types"]) else None
    owners, salt, iterations = hashed(parent, proof)
    if not owners:
        return None
    exact = owners.get(nsec3_hash(zone, salt, iterations))
    if exact:
        return "NSEC3" if delegation(checked(exact)["value"]["types"]) else None
    # Opt-out (5155 section 7.2.4): the record covering the name below the closest encloser is
    # flagged opt-out, so unsigned children like zone are skipped by the chain.
    found = closest_encloser(zone, parent, owners, salt, iterations)
    if found and found[2]["value"]["flags"] & 1:
        checked(found[1])
        checked(found[2])
        return "NSEC3 opt-out"
    return None


def proves_missing(name, qtype, zone, proof, sigs, keys, now):
    # How zone's signed NSEC or NSEC3 records show name has no qtype records, or is not there at all.
    # Returns the words for the chain, or None if they show neither.
    checked = checker(zone, sigs, keys, now)
    kind = resolve.TYPE_NAMES.get(qtype, qtype)
    # A name with no qtype and no CNAME; a parent's record for a delegation says nothing of the child's types.
    absent = lambda types: qtype not in types and resolve.CNAME not in types and (
        qtype == resolve.DS or resolve.NS not in types or resolve.SOA in types)
    nsec = [r for r in proof if r["type"] == resolve.NSEC and resolve.under(r["name"].lower(), zone)]
    for r in nsec:
        if r["name"].lower() == name:
            return f"{name} has no {kind} records: {zone or '.'} proves it with NSEC" if absent(checked(r)["value"]["types"]) else None
    if nsec:
        # RFC 4035 section 5.4: one NSEC covers the name, and one covers the wildcard at its closest
        # encloser, the longest name both the name and that record's ends sit under.
        def enclosing(r):
            if not covers(order(r["name"]), order(r["value"]["next"]), order(name)):
                return None
            types = r["value"]["types"]
            if resolve.under(name, r["name"].lower()) and resolve.NS in types and resolve.SOA not in types:
                return None  # the name is in a child zone, which this zone cannot speak for
            ends = [order(r["name"]), order(r["value"]["next"])]
            return max((e[:i] for e in ends for i in range(min(len(e), len(order(name)) - 1) + 1) if order(name)[:i] == e[:i]), key=len)
        for r in nsec:
            encloser = enclosing(r)
            if encloser is None:
                continue
            star = order("*." + ".".join(label.decode("latin-1") for label in reversed(encloser)))
            wild = next((w for w in nsec if covers(order(w["name"]), order(w["value"]["next"]), star)), None)
            if wild:
                checked(r)
                checked(wild)
                return f"{name} does not exist: {zone or '.'} proves it with NSEC"
        return None
    owners, salt, iterations = hashed(zone, proof)
    if not owners:
        return None
    exact = owners.get(nsec3_hash(name, salt, iterations))
    if exact:
        return f"{name} has no {kind} records: {zone or '.'} proves it with NSEC3" if absent(checked(exact)["value"]["types"]) else None
    found = closest_encloser(name, zone, owners, salt, iterations)
    if not found:
        return None
    encloser, match, cover = found
    star = nsec3_hash("*." + encloser if encloser else "*", salt, iterations)
    wild = next((r for owner, r in owners.items() if covers(owner, r["value"]["next"], star)), None)
    if not wild:
        return None
    for r in (match, cover, wild):
        checked(r)
    if cover["value"]["flags"] & 1:
        # Opt-out: an unsigned delegation could sit there, so the name's absence is not proven.
        raise Insecure(f"{name} falls in an opt-out span of {zone or '.'}, where unsigned names are not listed")
    return f"{name} does not exist: {zone or '.'} proves it with NSEC3"


def zone_keys(zone, fetch, now, chain, seen):
    # A zone's keys are trusted once its key-signing key matches a DS its parent signed (or, at the
    # root, the anchor) and that key has signed the whole DNSKEY set.
    if zone in seen:
        return seen[zone]
    keys, key_sigs = fetch(zone, resolve.DNSKEY)
    keys = [k for k in keys if k["type"] == resolve.DNSKEY]
    if zone == "":
        trusted = [k for k in keys if any(tag == key_tag(k) and alg == k["wire"][3]
                                          and hashlib.sha256(b"\0" + k["wire"]).digest() == digest
                                          for (tag, alg, _), digest in ANCHORS.items())]
        if not trusted:
            raise Bogus("no root DNSKEY matches the trust anchor")
    else:
        records, ds_sigs = fetch(zone, resolve.DS)
        ds = [d for d in records if d["type"] == resolve.DS and d["name"].lower() == zone]
        parent = ds_sigs[0]["rrsig"]["signer"] if ds_sigs else zone.partition(".")[2]
        if not resolve.under(zone, parent) or parent == zone:
            raise Bogus(f"the DS of {zone} is signed by {parent}, which is not above it")
        parent_keys = zone_keys(parent, fetch, now, chain, seen)
        if not ds:
            # A signed parent must prove the DS is missing, or someone may have just dropped it.
            how = proves_no_ds(zone, parent, records, ds_sigs, parent_keys, now)
            if not how:
                raise Bogus(f"{zone} has no DS in {parent or '.'}, and nothing {parent or '.'} signed proves that")
            raise Insecure(f"{zone} is not signed: {parent or '.'} proves it has no DS, with {how}")
        verify(ds, ds_sigs, parent_keys, parent, now)
        trusted = [k for k in keys if any(matches_ds(k, zone, d) for d in ds)]
        if not trusted:
            raise Bogus(f"no DNSKEY of {zone} matches its DS in {parent or '.'}")
    if not keys:
        raise Bogus(f"{zone or '.'} has no DNSKEY records")
    signer = verify(keys, key_sigs, trusted, zone, now)
    chain.append(f"{zone or '.'} key {key_tag(signer)} ({ALGORITHMS.get(signer['wire'][3], signer['wire'][3])}), "
                 + ("the root trust anchor" if zone == "" else "vouched for by a DS in " + (parent or ".")))
    seen[zone] = keys
    return keys


def zone_of(name, fetch):
    # The zone a name is in: the nearest name at or above it that has an SOA record, its apex.
    labels = name.split(".") if name else []
    for i in range(len(labels)):
        apex = ".".join(labels[i:])
        if any(r["type"] == resolve.SOA and r["name"].lower() == apex for r in fetch(apex, resolve.SOA)[0]):
            return apex
    return ""


def denial(name, qtype, proof, sigs, fetch, now, chain, seen):
    # The proven words for an empty answer; raises Bogus if the proof fails or never came.
    sigs = [s for s in sigs if s["rrsig"]["covered"] in (resolve.NSEC, resolve.NSEC3)]
    if not sigs:
        apex = zone_of(name, fetch)
        zone_keys(apex, fetch, now, chain, seen)  # raises Insecure, with the proof, if apex is unsigned
        raise Bogus(f"{name} {resolve.TYPE_NAMES.get(qtype, qtype)} came back empty with no signed proof, but its zone {apex or '.'} is signed")
    zone = sigs[0]["rrsig"]["signer"]
    if not resolve.under(name, zone):
        raise Bogus(f"the denial for {name} is signed by {zone or '.'}, which is not above it")
    how = proves_missing(name, qtype, zone, proof, sigs, zone_keys(zone, fetch, now, chain, seen), now)
    if not how:
        raise Bogus(f"nothing {zone or '.'} signed proves {name} has no {resolve.TYPE_NAMES.get(qtype, qtype)} records")
    return how


def validate(name, qtype, fetch=lookup, now=None):
    # The answer to name/qtype with how it was proven, following CNAMEs (each one signed too).
    # Raises Bogus for a forgery or a broken chain and Insecure for an answer no one signed.
    now = int(time.time()) if now is None else now
    name, chain, seen = name.rstrip(".").lower(), [], {}
    for _ in range(8):
        records, sigs = fetch(name, qtype)
        here = [r for r in records if r["name"].lower() == name and r["type"] == qtype]
        if not here:
            alias, alias_sigs = fetch(name, resolve.CNAME)
            alias = [r for r in alias if r["name"].lower() == name and r["type"] == resolve.CNAME]
            if not alias:
                return [], chain + [denial(name, qtype, records, sigs, fetch, now, chain, seen)]
            here, sigs, qtype_here = alias, alias_sigs, resolve.CNAME
        else:
            qtype_here = qtype
        sigs = [s for s in sigs if s["rrsig"]["covered"] == qtype_here and s["name"].lower() == name]
        if not sigs:
            # Unsigned is only fine in an unsigned zone; in a signed one the signatures were stripped.
            # zone_keys raises Insecure, with the proof, if the zone really is unsigned.
            apex = zone_of(name, fetch)
            zone_keys(apex, fetch, now, chain, seen)
            raise Bogus(f"{name} {resolve.TYPE_NAMES.get(qtype_here)} came back unsigned, but its zone {apex or '.'} is signed")
        zone = sigs[0]["rrsig"]["signer"]
        signer = verify(here, sigs, zone_keys(zone, fetch, now, chain, seen), zone, now)
        chain.append(f"{name} {resolve.TYPE_NAMES.get(qtype_here)} signed by {zone} key {key_tag(signer)}")
        if qtype_here == qtype:
            return here, chain
        name = here[0]["value"].lower()
    raise Bogus("too many CNAMEs")
