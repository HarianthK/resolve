# Run: python test_dnssec.py. Replays real signed answers recorded in test_dnssec.json, then
# tampers with them; the last check asks the real servers. DOCS.md has how the file was made.
import base64
import copy
import hashlib
import json
import os
import struct
import sys
import time

import dnssec
import resolve

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_dnssec.json")
RECORDED = [("www.ietf.org", resolve.A), ("www.sidn.nl", resolve.A), ("isc.org", resolve.MX), ("nlnetlabs.nl", resolve.A), ("github.com", resolve.A),
            ("google.se", resolve.A), ("google.nl", resolve.A), ("nosuchname-xq.nlnetlabs.nl", resolve.A), ("nlnetlabs.nl", resolve.SRV),
            ("nosuchname-xq.ietf.org", resolve.A), ("nosuchname-xq.nl", resolve.A), ("nl", resolve.SRV), ("nosuchname-xq.com", resolve.A),
            ("zq9x-wild.dnsviz.net", resolve.A), ("a.b.zq9x.dnsviz.net", resolve.A), ("dnsviz.net", resolve.A)]

if "--record" in sys.argv:
    # Asks the real servers for RECORDED and writes every lookup the checks made, bytes as hex.
    found, now = {}, int(time.time())
    # NSEC and NSEC3 values hold bytes and sets, so those are parsed again from wire on loading.
    as_json = lambda r: dict(r, wire=r["wire"].hex(), **({"rrsig": dict(r["rrsig"], signature=r["rrsig"]["signature"].hex())} if "rrsig" in r else {}),
                             **({"value": None} if r["type"] in (resolve.NSEC, resolve.NSEC3) else {}))

    def recording(name, qtype):
        records, sigs = dnssec.lookup(name, qtype)
        found[f"{name}|{qtype}"] = [[as_json(r) for r in records], [as_json(s) for s in sigs]]
        return records, sigs
    for name, qtype in RECORDED:
        try:
            dnssec.validate(name, qtype, fetch=recording, now=now)
        except (dnssec.Bogus, dnssec.Insecure):
            pass
    json.dump({"now": now, "answers": found}, open(FIXTURE, "w"), indent=0, sort_keys=True)
    sys.exit(f"recorded {len(found)} lookups at {now}; if a zone has rolled its keys, update the key tags the checks below expect")

saved = json.load(open(FIXTURE))
NOW = saved["now"]


def from_json(r):
    r = dict(r, wire=bytes.fromhex(r["wire"]))
    if r["type"] in (resolve.NSEC, resolve.NSEC3):
        packed = resolve.name_wire(r["name"]) + struct.pack("!HHIH", r["type"], 1, r["ttl"], len(r["wire"])) + r["wire"]
        r["value"] = resolve.read_record(packed, 0)[0]["value"]
    if "rrsig" in r:
        r["rrsig"] = dict(r["rrsig"], signature=bytes.fromhex(r["rrsig"]["signature"]))
    return r


ANSWERS = {key: ([from_json(r) for r in records], [from_json(s) for s in sigs]) for key, (records, sigs) in saved["answers"].items()}


def replay(answers=ANSWERS):
    def fetch(name, qtype):
        records, sigs = answers.get(f"{name}|{qtype}", ([], []))
        return copy.deepcopy(records), copy.deepcopy(sigs)
    return fetch


def outcome(name, qtype, answers=ANSWERS, now=NOW):
    try:
        records, chain = dnssec.validate(name, qtype, fetch=replay(answers), now=now)
        return "secure", chain
    except dnssec.Bogus as e:
        return "bogus", str(e)
    except dnssec.Insecure as e:
        return "insecure", str(e)


def changed(key, part, index, edit):
    # A copy of the recorded answers with one record (part 0) or signature (part 1) edited.
    answers = copy.deepcopy(ANSWERS)
    edit(answers[key][part][index])
    return answers


def flip(field, at=-1):
    def edit(r):
        data = bytearray(r[field])
        data[at] ^= 1
        r[field] = bytes(data)
    return edit


def flip_signature(r):
    sig = bytearray(r["rrsig"]["signature"])
    sig[10] ^= 1
    r["rrsig"]["signature"] = bytes(sig)


# The curve itself: the base point is on it, and N copies of it add up to nothing, as its order says.
assert dnssec.on_curve(dnssec.G) and dnssec.times(dnssec.N, dnssec.G) is None
assert not dnssec.on_curve((dnssec.G[0], dnssec.G[1] + 1))
# Ed25519 against RFC 8032 section 7.1's first two vectors, and the second with its message changed.
pub1 = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
sig1 = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
pub2 = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
sig2 = bytes.fromhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
assert dnssec.ed25519_ok(pub1, sig1, b"") and dnssec.ed25519_ok(pub2, sig2, b"\x72")
assert not dnssec.ed25519_ok(pub2, sig2, b"\x73") and not dnssec.ed25519_ok(pub1, sig2, b"\x72")
# RFC 4034 appendix B's key tag, on the root's KSK-2017, whose tag is published as 20326.
root_keys = ANSWERS["|48"][0]
assert 20326 in [dnssec.key_tag(k) for k in root_keys], [dnssec.key_tag(k) for k in root_keys]

# Every recorded answer proves out, through RSA at the root, org and nlnetlabs.nl and ECDSA below.
for name, qtype, last in [("www.ietf.org", resolve.A, "www.ietf.org A signed by ietf.org key 34505"),
                          ("www.sidn.nl", resolve.A, "sidn.nl A signed by sidn.nl key 30794"),
                          ("isc.org", resolve.MX, "isc.org MX signed by isc.org key 27566"),
                          ("nlnetlabs.nl", resolve.A, "nlnetlabs.nl A signed by nlnetlabs.nl key 42393")]:
    result, chain = outcome(name, qtype)
    assert result == "secure" and chain[-1] == last and chain[0].startswith(". key "), (name, result, chain)
result, chain = outcome("www.sidn.nl", resolve.A)
assert "www.sidn.nl CNAME signed by sidn.nl key 30794" in chain, chain  # the alias is signed too
result, why = outcome("github.com", resolve.A)
assert result == "insecure" and "no DS" in why, why
print("five recorded answers: four proven up to the root's key through RSA and ECDSA, github.com unsigned")

# Now forgeries. Each changes one thing an attacker on the path could change, and each is refused.
a_key = "www.ietf.org|1"
cases = [
    ("an address changed", changed(a_key, 0, 0, flip("wire")), "www.ietf.org", resolve.A, "verifies"),
    ("a bit of the signature changed", changed(a_key, 1, 0, flip_signature), "www.ietf.org", resolve.A, "verifies"),
    ("the signature stripped", changed(a_key, 1, 0, lambda r: r["rrsig"].update(covered=0)), "www.ietf.org", resolve.A, "is signed"),
    ("ietf.org's DS in org changed", changed("ietf.org|43", 0, 0, flip("wire")), "www.ietf.org", resolve.A, "verifies"),
    ("org's key changed", changed("org|48", 0, 0, flip("wire")), "www.ietf.org", resolve.A, "verifies"),
    ("an MX name upper-cased", changed("isc.org|15", 0, 0, lambda r: r.update(wire=r["wire"][:2] + r["wire"][2:].upper())), "isc.org", resolve.MX, "verifies"),
    ("a DS signed by the zone itself", changed("ietf.org|43", 1, 0, lambda r: r["rrsig"].update(signer="ietf.org")), "www.ietf.org", resolve.A, "not above"),
]
for why, answers, name, qtype, words in cases:
    result, reason = outcome(name, qtype, answers)
    assert result == "bogus" and words in reason, (why, result, reason)
# The signatures are only good for a few days, so the same answers a year later are refused.
result, reason = outcome("www.ietf.org", resolve.A, now=NOW + 365 * 86400)
assert result == "bogus" and "not now" in reason, reason
# And with a trust anchor that is not the root's real key, nothing proves out.
real = dnssec.ANCHORS
dnssec.ANCHORS = {k: bytes(32) for k in real}
try:
    result, reason = outcome("www.ietf.org", resolve.A)
    assert result == "bogus" and "trust anchor" in reason, reason
finally:
    dnssec.ANCHORS = real
# A changed TTL is not a forgery: the signature covers the TTL the signer set, not the cached one.
result, _ = outcome("www.ietf.org", resolve.A, changed(a_key, 0, 0, lambda r: r.update(ttl=5)))
assert result == "secure", result
# Nor is case: DNS names ignore it, so the signer signed the lower-case owner (RFC 4034 6.2).
mixed = copy.deepcopy(ANSWERS)
for r in mixed[a_key][0] + mixed[a_key][1]:
    r["name"] = "WWW.IeTf.org"
result, _ = outcome("www.ietf.org", resolve.A, mixed)
assert result == "secure", result
print(f"{len(cases) + 2} forgeries refused as bogus; a changed cache TTL or the owner's case still proves out")

# The attack the DS exists for: a key of the attacker's own, which signs its own key set and the
# answer perfectly well. Only the parent's DS, a hash of the real key, tells the two apart.
import random
import struct
rng = random.Random(7)
secret = rng.randrange(1, dnssec.N)
x, y = dnssec.times(secret, dnssec.G)
fake = {"name": "ietf.org", "type": resolve.DNSKEY, "ttl": 3600, "wire": struct.pack("!HBB", 257, 3, 13) + x.to_bytes(32, "big") + y.to_bytes(32, "big")}


def sign_with_fake(sig, rrset):
    # The signature's fields with the fake key's tag, then a real ECDSA signature by that key.
    r = sig["rrsig"]
    r["key_tag"] = dnssec.key_tag(fake)
    sig["wire"] = struct.pack("!HBBIIIH", r["covered"], 13, r["labels"], r["original_ttl"], r["expiration"], r["inception"], r["key_tag"]) + resolve.name_wire(r["signer"])
    e = int.from_bytes(dnssec.hashlib.sha256(dnssec.signed_data(sig, rrset)).digest(), "big")
    k = rng.randrange(1, dnssec.N)
    point_r = dnssec.times(k, dnssec.G)[0] % dnssec.N
    r["signature"] = point_r.to_bytes(32, "big") + (pow(k, -1, dnssec.N) * (e + point_r * secret) % dnssec.N).to_bytes(32, "big")


taken = copy.deepcopy(ANSWERS)
taken["ietf.org|48"] = ([fake], [taken["ietf.org|48"][1][0]])
sign_with_fake(taken["ietf.org|48"][1][0], [fake])
sign_with_fake(taken[a_key][1][0], taken[a_key][0])
assert dnssec.verify([fake], taken["ietf.org|48"][1], [fake], "ietf.org", NOW) == fake  # the forgery is well made
result, reason = outcome("www.ietf.org", resolve.A, taken)
assert result == "bogus" and "matches its DS" in reason, (result, reason)
print("an attacker's own key, signing its own key set and the answer, is refused: no DS vouches for it")

# An unsigned zone is only insecure if its signed parent proves there is no DS, in one of the
# three ways: NSEC (se), NSEC3 matching the name (nl), and NSEC3 opt-out covering it (com).
assert base64.b32hexencode(dnssec.nsec3_hash("example", bytes.fromhex("aabbccdd"), 12)).decode().lower() == "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom"  # RFC 5155 appendix A
for name, how in [("google.se", "with NSEC"), ("google.nl", "with NSEC3"), ("github.com", "with NSEC3 opt-out")]:
    result, why = outcome(name, resolve.A)
    assert result == "insecure" and why.endswith(how), (name, result, why)
# Dropping the DS of a signed zone is the downgrade this stops: the proof is gone, or belongs to
# another name (github.com's, replayed for cloudflare.com), or has lost its signature.
no_proof = copy.deepcopy(ANSWERS)
no_proof["github.com|43"] = ([r for r in no_proof["github.com|43"][0] if r["type"] == resolve.SOA], no_proof["github.com|43"][1])
replayed = copy.deepcopy(ANSWERS)
replayed["cloudflare.com|43"] = copy.deepcopy(ANSWERS["github.com|43"])
replayed["cloudflare.com|1"] = copy.deepcopy(ANSWERS["github.com|1"])  # unsigned, as an attacker would send it
replayed["cloudflare.com|6"] = copy.deepcopy(ANSWERS["github.com|6"])  # and an SOA, so the zone is found
for row in replayed["cloudflare.com|1"][0] + replayed["cloudflare.com|6"][0]:
    row["name"] = "cloudflare.com"
# And a name nl says does not exist, passed off as an unsigned zone: nl's spans are not opt-out.
for source, key in [("nosuchname-xq.nl|1", "|43"), ("github.com|1", "|1"), ("github.com|6", "|6")]:
    replayed["nosuchname-xq.nl" + key] = copy.deepcopy(ANSWERS[source])
    for row in replayed["nosuchname-xq.nl" + key][0] if key != "|43" else []:
        row["name"] = "nosuchname-xq.nl"
unsigned_proof = copy.deepcopy(ANSWERS)
unsigned_proof["google.nl|43"] = (unsigned_proof["google.nl|43"][0], [s for s in unsigned_proof["google.nl|43"][1] if s["rrsig"]["covered"] != resolve.NSEC3])
unsigned_proof["google.se|43"] = (unsigned_proof["google.se|43"][0], [s for s in unsigned_proof["google.se|43"][1] if s["rrsig"]["covered"] != resolve.NSEC])
# For opt-out, only the covering record's signature goes; the one matching com itself stays signed.
covering = [r["name"] for r in ANSWERS["github.com|43"][0] if r["type"] == resolve.NSEC3 and resolve.SOA not in r["value"]["types"]]
unsigned_proof["github.com|43"] = (unsigned_proof["github.com|43"][0], [s for s in unsigned_proof["github.com|43"][1] if s["name"] not in covering])
for why, answers, name, words in [("the NSEC3 records removed", no_proof, "github.com", "nothing com signed proves"),
                                  ("github.com's denial replayed for cloudflare.com", replayed, "cloudflare.com", "nothing com signed proves"),
                                  ("a missing name passed off as an unsigned zone", replayed, "nosuchname-xq.nl", "nothing nl signed proves"),
                                  ("the NSEC3 signatures removed", unsigned_proof, "google.nl", "NSEC3 has no signature"),
                                  ("the covering opt-out NSEC3's signature removed", unsigned_proof, "github.com", "NSEC3 has no signature"),
                                  ("the NSEC signatures removed", unsigned_proof, "google.se", "NSEC has no signature")]:
    result, reason = outcome(name, resolve.A, answers)
    assert result == "bogus" and words in reason, (why, result, reason)
print("missing DS records proven by NSEC, NSEC3 and NSEC3 opt-out; six forged denials refused")

# Empty answers are proven too: no such name and no such record, by NSEC, NSEC3, and the one-record
# NSEC some signers make up on the fly (ietf.org's). A denial in an opt-out span proves nothing.
for name, qtype, words in [("nosuchname-xq.nlnetlabs.nl", resolve.A, "does not exist: nlnetlabs.nl proves it with NSEC"),
                           ("nlnetlabs.nl", resolve.SRV, "has no SRV records: nlnetlabs.nl proves it with NSEC"),
                           ("nosuchname-xq.ietf.org", resolve.A, "has no A records: ietf.org proves it with NSEC"),
                           ("nosuchname-xq.nl", resolve.A, "does not exist: nl proves it with NSEC3"),
                           ("nl", resolve.SRV, "has no SRV records: nl proves it with NSEC3")]:
    result, chain = outcome(name, qtype)
    assert result == "secure" and chain[-1] == f"{name} {words}", (name, result, chain)
result, why = outcome("nosuchname-xq.com", resolve.A)
assert result == "insecure" and "opt-out span of com" in why, why
# An attacker who wants a real name to vanish must forge or misuse the proof, and each way is refused.
nx, nodata = "nosuchname-xq.nlnetlabs.nl|1", "nlnetlabs.nl|33"
forged = []
wild_gone = copy.deepcopy(ANSWERS)
wild_gone[nx] = ([r for r in wild_gone[nx][0] if r["name"] != "nlnetlabs.nl" or r["type"] != resolve.NSEC], wild_gone[nx][1])
forged.append(("the NSEC covering the wildcard removed", wild_gone, "nosuchname-xq.nlnetlabs.nl", resolve.A, "nothing nlnetlabs.nl signed proves"))
forged.append(("the wildcard NSEC's signature removed", changed(nx, 1, [(s["name"], s["rrsig"]["covered"]) for s in ANSWERS[nx][1]].index(("nlnetlabs.nl", resolve.NSEC)), lambda r: r["rrsig"].update(covered=0)),
               "nosuchname-xq.nlnetlabs.nl", resolve.A, "NSEC has no signature"))
# A name at the very end of an NSEC's span exists; the span only covers what lies strictly inside.
ends = copy.deepcopy(ANSWERS)
ends["6only.nlnetlabs.nl|1"] = copy.deepcopy(ANSWERS[nx])
forged.append(("the denial replayed for the name its NSEC ends at", ends, "6only.nlnetlabs.nl", resolve.A, "signed proves"))
forged.append(("the covering NSEC's signature removed", changed(nx, 1, [s["name"] for s in ANSWERS[nx][1]].index("norrsigs.nlnetlabs.nl"), lambda r: r["rrsig"].update(covered=0)),
               "nosuchname-xq.nlnetlabs.nl", resolve.A, "NSEC has no signature"))
unsigned = copy.deepcopy(ANSWERS)
unsigned[nx] = (unsigned[nx][0], [])
forged.append(("the whole denial unsigned", unsigned, "nosuchname-xq.nlnetlabs.nl", resolve.A, "no signed proof"))
for victim, qtype, source in [("nlnetlabs.nl", resolve.A, nodata), ("www.ietf.org", resolve.A, "nosuchname-xq.ietf.org|1"), ("nl", resolve.NS, "nl|33")]:
    replayed = copy.deepcopy(ANSWERS)
    replayed[f"{victim}|{qtype}"] = copy.deepcopy(ANSWERS[source])
    forged.append((f"{source}'s denial replayed for {victim}", replayed, victim, qtype, "signed proves"))
for i, r in enumerate(ANSWERS["nosuchname-xq.nl|1"][0]):
    if r["type"] == resolve.NSEC3:
        dropped = copy.deepcopy(ANSWERS)
        dropped["nosuchname-xq.nl|1"][0].pop(i)
        forged.append((f"NSEC3 {r['name']} removed", dropped, "nosuchname-xq.nl", resolve.A, "nothing nl signed proves"))
        stripped = copy.deepcopy(ANSWERS)
        stripped["nosuchname-xq.nl|1"][1][:] = [s for s in stripped["nosuchname-xq.nl|1"][1] if s["name"] != r["name"]]
        forged.append((f"NSEC3 {r['name']}'s signature removed", stripped, "nosuchname-xq.nl", resolve.A, "NSEC3 has no signature"))
for why, answers, name, qtype, words in forged:
    result, reason = outcome(name, qtype, answers)
    assert result == "bogus" and words in reason, (why, result, reason)
print(f"five empty answers proven, an opt-out one insecure; {len(forged)} forged denials refused")

# A wildcard's answer is signed for *.dnsviz.net, so it needs proof that the name asked for is not there.
for name in ("zq9x-wild.dnsviz.net", "a.b.zq9x.dnsviz.net"):
    result, chain = outcome(name, resolve.A)
    assert result == "secure" and f"{name} is from the wildcard *.dnsviz.net: dnsviz.net proves no closer name with NSEC" in chain, (name, result, chain)
wild = "zq9x-wild.dnsviz.net|5"
forged = []
no_proof = copy.deepcopy(ANSWERS)
no_proof[wild] = ([r for r in no_proof[wild][0] if r["type"] != resolve.NSEC], no_proof[wild][1])
forged.append(("the NSEC removed", no_proof, "zq9x-wild.dnsviz.net", "came from a wildcard"))
unsigned = copy.deepcopy(ANSWERS)
unsigned[wild] = (unsigned[wild][0], [s for s in unsigned[wild][1] if s["rrsig"]["covered"] != resolve.NSEC])
forged.append(("the NSEC's signature removed", unsigned, "zq9x-wild.dnsviz.net", "NSEC has no signature"))
# The attack itself: the wildcard's signed CNAME replayed for www.dnsviz.net, which exists, and for a
# name under it, which the NSEC would cover if it were checked against the full name, not the next closer.
for victim in ("www.dnsviz.net", "a.www.dnsviz.net"):
    replayed = copy.deepcopy(ANSWERS)
    replayed[f"{victim}|5"] = copy.deepcopy(ANSWERS[wild])
    for r in replayed[f"{victim}|5"][0] + replayed[f"{victim}|5"][1]:
        if r["type"] == resolve.CNAME or r["type"] == resolve.RRSIG and r["rrsig"]["covered"] == resolve.CNAME:
            r["name"] = victim
    forged.append((f"the wildcard replayed for {victim}", replayed, victim, "came from a wildcard"))
for why, answers, name, words in forged:
    result, reason = outcome(name, resolve.A, answers)
    assert result == "bogus" and words in reason, (why, result, reason)
print(f"two wildcard answers proven; {len(forged)} forged ones refused, among them the wildcard replayed over a real name")

# No live zone was found that proves a wildcard with NSEC3, so this is RFC 5155 appendix B.4's reply, record for
# record. Its RSA/SHA-1 signatures are retired, so the test signs it again with its own Ed25519 key.
SECRET = hashlib.sha512(b"rfc5155 b.4").digest()
SCALAR = int.from_bytes(SECRET[:32], "little") & (2 ** 254 - 8) | 2 ** 254
point_bytes = lambda p: (p[1] | (p[0] & 1) << 255).to_bytes(32, "little")
PUBLIC = point_bytes(dnssec.ed_times(SCALAR, dnssec.ED_BASE))
INCEPTION, EXPIRATION = 1129852800, 1429574399  # 20051021000000 and 20150420235959, as in the RFC


def ed_sign(data):
    # RFC 8032 section 5.1.6, the other half of what dnssec.ed25519_ok checks.
    r = int.from_bytes(hashlib.sha512(SECRET[32:] + data).digest(), "little") % dnssec.EL
    big_r = point_bytes(dnssec.ed_times(r, dnssec.ED_BASE))
    h = int.from_bytes(hashlib.sha512(big_r + PUBLIC + data).digest(), "little") % dnssec.EL
    return big_r + ((r + h * SCALAR) % dnssec.EL).to_bytes(32, "little")


def rfc_reply(nsec3_flags, qname="a.z.w.example"):
    # The answer is signed over its unexpanded owner, "*.w.example", spelled out here rather than taken from dnssec.
    rr = lambda name, rtype, rdata: resolve.name_wire(name) + struct.pack("!HHIH", rtype, 1, 3600, len(rdata)) + rdata
    def signed(name, rtype, labels, rdata, over):
        head = struct.pack("!HBBIIIH", rtype, 15, labels, 3600, EXPIRATION, INCEPTION, rfc_tag) + resolve.name_wire("example")
        return rr(name, resolve.RRSIG, head + ed_sign(head + rr(over, rtype, rdata)))
    key = struct.pack("!HBB", 256, 3, 15) + PUBLIC
    rfc_tag = dnssec.key_tag({"wire": key})
    mx = struct.pack("!H", 1) + resolve.name_wire("ai.example")
    cover = "q04jkcevqvmu85r014c7dkba38o0ji5r.example"
    # NSEC3 1 1 12 aabbccdd r53bq7cc2uvmubfu5ocmm6pers9tk9en A RRSIG: types 1 and 46 in window 0.
    nsec3 = (struct.pack("!BBHB", 1, nsec3_flags, 12, 4) + bytes.fromhex("aabbccdd") + b"\x14"
             + base64.b32hexdecode("R53BQ7CC2UVMUBFU5OCMM6PERS9TK9EN") + bytes([0, 6, 0x40, 0, 0, 0, 0, 2]))
    answer = [rr(qname, resolve.MX, mx), signed(qname, resolve.MX, 2, mx, "*.w.example")]
    authority = [rr(cover, resolve.NSEC3, nsec3), signed(cover, resolve.NSEC3, 2, nsec3, cover)]
    message = struct.pack("!HHHHHH", 0, 0x8400, 0, 2, 2, 1) + b"".join(answer + authority) + rr("example", resolve.DNSKEY, key)
    return resolve.parse(message)


def rfc_outcome(reply, qname="a.z.w.example", now=1300000000):
    keys = reply["additional"]
    proof = [r for r in reply["authority"] if r["type"] != resolve.RRSIG]
    sigs = [r for r in reply["authority"] if r["type"] == resolve.RRSIG]
    dnssec.verify(reply["answers"][:1], reply["answers"][1:], keys, "example", now)
    try:
        return dnssec.proves_expansion(qname, reply["answers"][1]["rrsig"]["labels"], "example", proof, sigs, keys, now) or "no proof"
    except (dnssec.Bogus, dnssec.Insecure) as e:
        return f"{type(e).__name__}: {e}"


reply = rfc_reply(0)
assert reply["authority"][0]["value"]["types"] == {resolve.A, resolve.RRSIG}
assert base64.b32hexencode(dnssec.nsec3_hash("z.w.example", bytes.fromhex("aabbccdd"), 12)).decode().lower() == "qlu7gtfaeh0ek0c05ksfhdpbcgglbe03"
said = rfc_outcome(reply)
assert said == "a.z.w.example is from the wildcard *.w.example: example proves no closer name with NSEC3", said
# As printed, the NSEC3 has opt-out set, and section 12.2 warns that an opt-out span lets signed wildcard expansions be forged.
said = rfc_outcome(rfc_reply(1))
assert said.startswith("Insecure:") and "opt-out" in said, said
forged = []
# x.w.example exists (appendix A), so its hash falls outside the span; so does a name under it.
for victim in ("x.w.example", "a.x.w.example"):
    forged.append((f"the wildcard replayed for {victim}", rfc_reply(0, victim), victim, "no proof"))
broken = rfc_reply(0)
broken["authority"][1]["rrsig"]["signature"] = bytes(64)
forged.append(("the NSEC3's signature zeroed", broken, "a.z.w.example", "Bogus: q04jkcevqvmu85r014c7dkba38o0ji5r.example NSEC3: no key"))
gone = rfc_reply(0)
gone["authority"] = gone["authority"][1:]
forged.append(("the NSEC3 removed", gone, "a.z.w.example", "no proof"))
for why, reply, name, words in forged:
    said = rfc_outcome(reply, name)
    assert said.startswith(words), (why, said)
print(f"RFC 5155's NSEC3 wildcard answer proven, insecure as printed with opt-out; {len(forged)} forgeries of it refused")

# The real thing, from the root down, today.
resolve.known = {"": resolve.known[""]}
resolve.answers.clear()
records, chain = dnssec.validate("cloudflare.com", resolve.A)
assert records and chain[-1].startswith("cloudflare.com A signed by cloudflare.com"), chain
print("cloudflare.com proven live:", " / ".join(chain))
# ed25519.nl, a test zone NLnet Labs keeps signed with Ed25519 only.
records, chain = dnssec.validate("ed25519.nl", resolve.A)
assert "(Ed25519), vouched for by a DS in nl" in chain[-2], chain
print("ed25519.nl proven live:", chain[-2])
print("ok")
