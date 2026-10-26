# What I learned writing a DNS resolver

## The packet is small and old

A query is 12 bytes of header, the name as length-prefixed labels
(`\x07example\x03com\x00`), then two 16-bit numbers for type and class. The
reply has the same header with counts for four sections: questions, answers,
authority, additional. That is the whole format, from 1987, and it is what
every device on the internet still sends.

## Recursion is a flag you can turn off

Byte 2 of the header holds the flags. The one everyone's resolver sets is RD,
"recursion desired": it asks a server like 8.8.8.8 to do the work. Leave it
off and a public resolver returns nothing, but an authoritative server
returns what it has: either an answer, or a referral to whoever is closer.
Following referrals yourself is called iterative resolution, and it is what
8.8.8.8 does on your behalf.

## A referral is the authority section plus glue

When a root server does not know `example.com`, it fills the authority
section with the NS records for `com` and the additional section with the
addresses of those servers. The addresses are "glue". Without them you would
have to resolve `a.gtld-servers.net` before you could ask it anything, and
resolving that needs the `.net` servers, which the root also has to tell you
about. Glue is only sent when the name server is inside the zone being
referred to; `pages.github.io` points at `dns3.p05.nsone.net`, which is not
under `.io`, so the `.io` servers send no glue and the resolver has to go
back to the root for the name server's own address first.

## Name compression is a pointer into the same packet

Names repeat constantly in a reply, so a name can be replaced anywhere by two
bytes with the top two bits set and a 14-bit offset into the packet. Reading a
name means following pointers, and the subtlety is where reading resumes: a
pointer ends the name, so the parser continues after the two pointer bytes,
not after the name it jumped to. Getting this wrong shifts every later record
and the parser reads garbage, which is why the test builds a packet with a
pointer by hand.

## 512 bytes was the limit

Plain DNS over UDP stops at 512 bytes. A server with more to say sends what
fits and sets the TC flag, and the client is expected to ask again over TCP,
where the message is prefixed by its length. `google.com TXT` has 17 records
and is truncated at 443 bytes; more surprisingly, the root's referral for
`.com` is truncated too, at 509 bytes, so a UDP-only client sees fewer glue
addresses than exist. EDNS0 raises the limit, but the fallback still has to
be there.

Now every query carries EDNS0: one extra record at the end, type OPT, with no
name, whose class field is not a class at all but the reply size the asker can
take. It asks for 1,232 bytes, the figure DNS Flag Day 2020 settled on because
a reply that size crosses any network without being split into fragments, and
fragments are what get lost and what spoofing attacks used to ride in on. With
it, `google.com TXT` comes back over UDP in one round trip instead of two plus
a TCP handshake. `microsoft.com TXT` is bigger still, 58 records, and still
falls back to TCP, as it should.

A server too old to know EDNS answers FORMERR, a format error, and the resolver
asks it again the 1987 way. That retry is only taken once the reply's id has
matched the query's, since otherwise anyone able to guess where a query was
going could forge a FORMERR and push every lookup back to plain DNS. The tests
run against a real UDP socket on this machine, playing a modern server, an old
one and a forger; nothing listens for TCP there, so a test that needed the TCP
fallback would fail rather than quietly pass.

## Caching is what makes the real thing fast

A lookup from nothing is three round trips for most names: root, top-level
domain, the name's own servers. A real resolver remembers every referral and
answer for its TTL, the number each record carries saying how many seconds it
may be kept, and this one now does too.

Answers are kept by name and type until their TTL is up, and a cached answer is
returned with the seconds it has left rather than the TTL it arrived with, as a
real resolver's is. Referrals are kept by zone with their own expiry, which is
usually far longer: `.com`'s name servers are good for two days, a site's
answer often for five minutes. So after an answer expires, the next lookup
starts at the site's own servers, one packet; only when those expire too does it
go back to `.com`, and only after two days to the root. An alias is kept for as
long as both the alias and what it points at are valid.

The test for this does not touch the network. A scripted fake answers as the
root, `.com` and a site would, counts every packet, and a clock that the test
controls jumps forward past each expiry in turn. It expects three packets, then
none, then one, then two, and each wrong expiry rule breaks a different one of
those.

## Remembering what does not exist

A name that does not exist costs the same three round trips as one that does,
and a typo or a probe for a missing name tends to be asked again. RFC 2308 says
how long to remember the answer: the server sends the zone's SOA record in the
authority section beside its NXDOMAIN, and the shorter of that record's own TTL
and its last field, the minimum, is the time. For example.com that is 1,800
seconds, so the second lookup of a made-up name under it takes no packets.

Two details are easy to get wrong. A missing name is missing for every type, so
the miss is kept by name, not by name and type: asking for its IPv6 address next
must not go back to the network. And an NXDOMAIN that arrives without an SOA
gives no time to keep it, so it is not kept at all. The offline test covers both,
and the SOA record is now decoded instead of shown as raw bytes.

## A zone has many servers because some are always down

Every referral names several servers, usually between two and thirteen, and
the first version picked one at random and gave up if it did not answer. That
is fine on a good day and wrong on an ordinary one: a delegation can point at
a server that no longer serves the zone, and some networks cannot reach some
root servers at all. Now each of the zone's servers is tried once, in random
order, before the lookup fails. A server that answers with the wrong query id
counts as not answering, since that reply could be a forgery.

The offline test lets .com have three servers, makes two of them time out, and
checks for each choice of survivor that the lookup succeeds without asking any
server twice, then that it fails cleanly when all three are silent.

## A server is only believed about its own zone

A reply can carry anything, and the first version believed all of it. Asked
about example.com, a .com server could answer with a record for bank.com and
it would be returned and cached as example.com's address. It could refer the
question to bank.org, and that referral would be cached for every later
lookup under bank.org. It could refer back to .com, and the loop following
referrals would never end. This is the hole cache poisoning used for years.

The fix is the bailiwick rule, which real resolvers apply to every reply:

- Only answer records whose name is the name asked are read.
- A referral must hand down a zone strictly between the server's zone and the
  name: example.com from a .com server, never bank.org and never .com again.
- Glue, the addresses that come with a referral, is believed only for name
  servers inside the server's own zone. A .com server can vouch for
  ns.example.com but not for ns.evil.org, whose address is looked up from the
  root instead.

The last rule costs real lookups a little: .com servers send glue for .net
name servers too, which is now ignored, so github.com takes extra queries to
find its name servers. Six real names still resolve. The offline test plays a
.com server that tries each of the four lies, and checks that each one fails
the lookup and that the planted address is never contacted or cached.

## Telling each server only what it needs

A classic resolver sends the whole name to every server on the way down. The
root, which only knows where `.org` lives, still learns that someone wanted
`en.wikipedia.org`. QNAME minimisation, RFC 9156, asks each server about the
next label below the zone it serves and nothing more: the root is asked about
`org`, the `.org` servers about `wikipedia.org`, and only Wikipedia's own servers
see the whole name and the record type actually wanted. The in-between
questions are asked as type A, which the RFC recommends over NS because some
servers mishandle NS questions.

Three things make it work on real servers. A name with no zone starting at it
comes back as an empty NOERROR, so the same servers are asked about the next
label down. A server that wrongly answers NXDOMAIN for such an empty name, an
old bug the RFC warns about, is not believed: the whole question is asked
instead, and nothing is remembered as missing on the strength of an in-between
answer. And after three in-between steps inside one zone, the whole name is
asked, as the RFC caps it, so a long name cannot cost a query per label.

The price is extra queries where a name has labels that are not zones.
`en.wikipedia.org` still takes five queries; `www.bbc.co.uk` went from six to
eleven, because `co.uk` is not a zone of its own and the CNAME it ends at,
`www.bbc.co.uk.pri.bbc.co.uk`, sits three non-zone labels deep. The cache makes
that a one-off. The tests check the exact names and types each server is asked,
the NXDOMAIN fallback, and the cap, and `MINIMISE = False` turns it all off.

## An old answer beats no answer

When a zone's servers all go quiet, a strict resolver fails every lookup the
moment its cached answers expire, even though those answers were very likely
still right. RFC 8767 lets a resolver keep using an expired answer in that one
situation. Here an expired answer up to a day old is given out when no server
answers at all, with a TTL of 30 seconds so whoever asked comes back soon and
gets a fresh one once the servers are up.

The line that matters is between no answer and an answer. A server that says
the name no longer exists has answered, and hiding that behind a stale address
would keep sending people to a name that is gone. So the timeouts that end a
lookup now raise their own error, `Unreachable`, and only that one is caught;
NXDOMAIN, a bailiwick violation and a CNAME loop all still fail. The test plays
an outage, a recovery, an answer past the one day limit and a name that
disappears, and each of four deliberate breakages makes one of them fail.

## Random source ports and IDs are the security

The query id is 16 bits and the reply must carry the same one. That, plus a
random source port, is all that stops someone on the path from answering
first with a lie. It is thin, which is why DNSSEC and DNS over HTTPS exist.

## Checking the signatures

DNSSEC does not hide anything; it signs. Each signed zone has keys in DNSKEY
records, and next to every set of records (all the A records of a name, say)
it publishes an RRSIG: which key signed, when the signature starts and stops
being valid, and the signature itself. A resolver that sets the DO bit in its
query gets the RRSIGs alongside the answer.

A signature only proves the zone's own key signed it, and anyone can make a
key. What makes it worth something is the chain. The zone's parent publishes
a DS record for it, a hash of the child's key-signing key, and the DS is itself
signed by the parent's keys, whose own DS sits in the grandparent, and so on up
to the root. The root has no parent, so its key is the one thing taken on
trust: `ANCHORS` holds the hashes IANA publishes of the two root keys, KSK-2017
(tag 20326) and KSK-2024 (tag 38696). Checking `cloudflare.com` is then:

1. the root's DNSKEY set, which must hold a key matching an anchor and be
   signed by it;
2. the DS for `com` in the root, signed by a root key;
3. `com`'s DNSKEY set, holding the key that DS hashes and signed by it;
4. the same again for `cloudflare.com` in `com`;
5. the A records, signed by one of `cloudflare.com`'s keys.

What gets signed is not the bytes that arrived. RFC 4034 section 6 defines a
canonical form: names spelled out in full (no compression pointers) and in
lower case, the records of a set sorted by their data, and the TTL the signer
set rather than the one a cache has been counting down. So the parser now
keeps a `wire` field for every record, its data with any names in it written
out that way. Each of those rules has a test that fails when the rule is
dropped: unsorted records break the root's two-key set, upper case breaks MX,
and a cached TTL of 5 still proves out.

The two algorithms nearly every zone uses are written out, with no crypto
library. RSA/SHA-256 (the root and `org`) is one modular exponentiation: raise
the signature to the key's exponent and the result must be the PKCS #1 v1.5
padding around the hash. ECDSA P-256 (`com`, Cloudflare, most zones signed
lately) is arithmetic on an elliptic curve: with the key a point Q and the
signature (r, s), the point (e/s)G + (r/s)Q must have r as its x coordinate,
where e is the hash. It takes about 30 milliseconds a signature in plain
Python. Checks run against signatures made by the zones' own signing software,
so a mistake in the arithmetic shows up as a real signature refused.

Three outcomes, not two. Secure means the chain held. Bogus means something
claims to be signed and the claim fails, and the answer is not printed at all.
Insecure means nothing says the answer should be signed: `github.com` has no DS
in `com`, so there is nothing to check it against. The trap is that an
attacker can also strip signatures from a signed answer. So an unsigned answer
is only insecure if its zone (the nearest name above it with an SOA) has no
DS; in a signed zone it is bogus.

ECDSA P-384, Ed448 and the old SHA-1 algorithms count as insecure, as RFC
4035 says to treat algorithms a validator does not know.

### Proving a DS is not there

"No DS, so insecure" was at first taken at the parent's word, and that was a
hole: an attacker who could stop a signed zone's DS from arriving got the zone
called insecure, not bogus, and its forged answers believed. A signed zone
cannot just say a name has nothing; it has to prove it, with records that list
what does exist and are signed like anything else.

NSEC (RFC 4034) is the plain version: an NSEC at a name gives the next name in
the zone, in canonical order, and every type this name has. So an NSEC at
`google.se`, signed by `se`, listing NS but not DS, proves `google.se` is a
delegation with no DS. NSEC lets anyone walk the whole zone by following the
next names, so most big zones use NSEC3 (RFC 5155) instead, which does the
same over hashed names: SHA-1 of the name and a salt, iterated, written in
base32hex as the record's first label. An NSEC3 whose hash is
`google.nl`'s, listing NS but not DS, proves the same thing for `nl`.

`com`, `org`, `net` and most others go one step further with opt-out. Their
millions of unsigned delegations get no NSEC3 records of their own at all. The
proof instead has two parts: an NSEC3 matching the closest name above that
does exist (`com` itself), and an NSEC3 flagged opt-out whose range of hashes
covers the next name down (`github.com`), which says "anything in here may be
an unsigned delegation". That is the weaker statement, but it is all that is
there to check, and it still stops a signed zone's DS from being dropped,
since a signed child always has its own NSEC3 with the DS bit set.

`dnssec.py` now checks all three, and every record the proof rests on must
carry the parent's valid signature. A missing DS with no such proof is bogus.
The same check runs when an answer arrives unsigned: its zone's keys are
looked up, and only a proven missing DS makes it insecure. NSEC3 with more
than 150 iterations is called insecure, as RFC 9276 allows, rather than spent
time on. The proofs that come with NODATA and NXDOMAIN answers themselves are
still not checked.

The parser keeps them now: a reply with no answer and no referral raises
`NoData`, a `LookupError` that carries the authority section, where the NSEC
or NSEC3 records and their signatures are. The hash is checked against RFC
5155's own example, `example` with salt `aabbccdd` and 12 iterations. The
test records `google.se` (NSEC), `google.nl` (NSEC3) and `github.com` (opt-out),
and refuses five forged denials: the proof removed, `github.com`'s proof
replayed for `cloudflare.com`, and the signatures taken off the NSEC3, the
covering opt-out NSEC3 and the NSEC. Six breakages fail it: hashing the
encloser instead of the next closer name, hashing the name's text instead of
its wire form, not checking the covering record's signature, not checking the
NSEC's, accepting a missing DS with no proof, and not tracing an unsigned
answer to its zone. Two of those first passed, because the tests that should
have caught them failed earlier for another reason; the tests now strip one
signature at a time.

### Ed25519

Algorithm 15 (RFC 8080) is Ed25519, on a different curve again, the twisted
Edwards curve -x^2 + y^2 = 1 + d x^2 y^2 modulo 2^255 - 19. Its addition law
is one formula with no special cases, not even for doubling or the identity,
which makes it the shortest of the three to write. A point travels as its y
with one bit for x's sign, so decoding takes a square root mod p. A signature
(R, S) holds when S times the base point equals R plus h times the key, h
being SHA-512 of R, the key and the signed data. It is checked against RFC
8032's own test vectors and, live, against `ed25519.nl` and `ed25519.no`,
two zones signed with nothing else.

Of three breakages, two fail the test (R and the key hashed in the wrong
order, the sign of d flipped). The third, inverting the sign bit when
decoding, changes nothing at all, and that is right: it negates every point
the same way, the base point included, and negating both sides of
S*B = R + h*A leaves it true. So it is not a bug a test could see.

### Two bugs it found in the resolver

The root itself had never been asked about. `build_query` wrote the empty name
as an empty label and then the end of the name, two zero bytes, and the root
servers called it a format error. It now writes names with `name_wire`, which
writes the root as the one zero byte it is.

And the cache sent DS questions to the wrong servers. Once `cloudflare.com`
has been looked up, its own servers are cached as the place to start for any
name under it, and they are asked for its DS. But the DS lives in the parent,
`com`, and the child's servers have nothing to say. A question for a DS now
never starts at the zone it is about.

### Testing it

`test_dnssec.py` replays answers recorded from the real servers on 2026-10-24
(`python test_dnssec.py --record` asks again), at the time they were
recorded, so the signatures are still in date. They cover RSA at the root,
`org` and `nlnetlabs.nl`, ECDSA in `com`, `nl` and the zones below, a CNAME
that is signed too (`www.sidn.nl`), an MX set (names inside the data), and an
unsigned zone. Then it forges: an address changed, a signature bit changed,
the signature stripped, a DS changed, `org`'s key changed, the MX names
upper-cased, a DS signed by the zone itself, the answers a year later, and a
trust anchor that is not the root's. The last is the attack the DS exists for:
an attacker's own ECDSA key that signs its own key set and the answer
correctly, and is refused only because no DS hashes it. Finally it proves
`cloudflare.com` live.

Eleven breakages, one at a time, each fail it: records left unsorted, names
left in their case, the validity window ignored, the key tag folded wrongly,
ECDSA's two multipliers swapped, the wrong RSA padding, keys trusted without
the DS, stripped signatures called insecure, a DS's signer not checked, the DS
asked of the child, and the root sent as two zero bytes. The first run of that
loop was wrong: two breakages failed with the previous breakage's message,
because a change of the same size, restored within the same second, left
Python's cached bytecode looking current. The loop now deletes `__pycache__`
and runs `python -B`.
