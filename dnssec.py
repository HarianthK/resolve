# DNSSEC validation: an answer is believed only if its signature chains up to the root zone's key.
# Run: python resolve.py cloudflare.com --dnssec. DOCS.md, "Checking the signatures", has the steps.
import hashlib
import struct
import time

import resolve

# The root's key-signing keys as IANA publishes them (root-anchors.xml), KSK-2017 and KSK-2024:
# (key tag, algorithm, digest type) -> SHA-256 of the key. Everything else is checked against these.
ANCHORS = {(20326, 8, 2): bytes.fromhex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
           (38696, 8, 2): bytes.fromhex("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16")}
ALGORITHMS = {8: "RSA/SHA-256", 10: "RSA/SHA-512", 13: "ECDSA P-256/SHA-256"}

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
                if r["algorithm"] in (8, 10) and rsa_ok(k[4:], r["signature"], data, "sha256" if r["algorithm"] == 8 else "sha512"):
                    return key
            reasons.append(f"no key {r['key_tag']} of {zone or '.'} verifies the signature")
    raise Bogus(f"{rrset[0]['name'] or '.'} {resolve.TYPE_NAMES.get(rrset[0]['type'])}: " + "; ".join(reasons))


def lookup(name, qtype):
    # The live way to fetch an RRset and its signatures; a test passes recorded answers instead.
    resolve.DNSSEC_OK = True
    try:
        records = resolve.resolve(name, qtype)
    except LookupError:
        return [], []
    return [r for r in records if r["type"] != resolve.RRSIG], [r for r in records if r["type"] == resolve.RRSIG]


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
        ds, ds_sigs = fetch(zone, resolve.DS)
        ds = [d for d in ds if d["type"] == resolve.DS and d["name"].lower() == zone]
        if not ds:
            # ponytail: a missing DS is taken at its word; proving it with NSEC/NSEC3 is the upgrade.
            raise Insecure(f"{zone} has no DS record in its parent, so it is not signed (the denial is not checked)")
        parent = ds_sigs[0]["rrsig"]["signer"] if ds_sigs else zone.partition(".")[2]
        if not resolve.under(zone, parent) or parent == zone:
            raise Bogus(f"the DS of {zone} is signed by {parent}, which is not above it")
        verify(ds, ds_sigs, zone_keys(parent, fetch, now, chain, seen), parent, now)
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
                raise Insecure(f"{name} has no {resolve.TYPE_NAMES.get(qtype, qtype)} records (a denial, which is not checked)")
            here, sigs, qtype_here = alias, alias_sigs, resolve.CNAME
        else:
            qtype_here = qtype
        sigs = [s for s in sigs if s["rrsig"]["covered"] == qtype_here and s["name"].lower() == name]
        if not sigs:
            # Unsigned is only fine in an unsigned zone; in a signed one the signatures were stripped.
            apex = zone_of(name, fetch)
            if apex == "" or any(d["type"] == resolve.DS for d in fetch(apex, resolve.DS)[0]):
                raise Bogus(f"{name} {resolve.TYPE_NAMES.get(qtype_here)} came back unsigned, but its zone {apex or '.'} is signed")
            raise Insecure(f"{name} {resolve.TYPE_NAMES.get(qtype_here)} came back unsigned, and its zone {apex} has no DS (not checked)")
        zone = sigs[0]["rrsig"]["signer"]
        signer = verify(here, sigs, zone_keys(zone, fetch, now, chain, seen), zone, now)
        chain.append(f"{name} {resolve.TYPE_NAMES.get(qtype_here)} signed by {zone} key {key_tag(signer)}")
        if qtype_here == qtype:
            return here, chain
        name = here[0]["value"].lower()
    raise Bogus("too many CNAMEs")
