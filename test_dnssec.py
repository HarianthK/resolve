# Run: python test_dnssec.py. Replays real signed answers recorded in test_dnssec.json, then
# tampers with them; the last check asks the real servers. DOCS.md has how the file was made.
import copy
import json
import os
import sys
import time

import dnssec
import resolve

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_dnssec.json")
RECORDED = [("www.ietf.org", resolve.A), ("www.sidn.nl", resolve.A), ("isc.org", resolve.MX), ("nlnetlabs.nl", resolve.A), ("github.com", resolve.A)]

if "--record" in sys.argv:
    # Asks the real servers for RECORDED and writes every lookup the checks made, bytes as hex.
    found, now = {}, int(time.time())
    as_json = lambda r: dict(r, wire=r["wire"].hex(), **({"rrsig": dict(r["rrsig"], signature=r["rrsig"]["signature"].hex())} if "rrsig" in r else {}))

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
