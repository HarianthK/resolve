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

## 512 bytes is still the limit

Plain DNS over UDP stops at 512 bytes. A server with more to say sends what
fits and sets the TC flag, and the client is expected to ask again over TCP,
where the message is prefixed by its length. `google.com TXT` has 17 records
and is truncated at 443 bytes; more surprisingly, the root's referral for
`.com` is truncated too, at 509 bytes, so a UDP-only client sees fewer glue
addresses than exist. EDNS0 raises the limit, but the fallback still has to
be there.

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

## Random source ports and IDs are the security

The query id is 16 bits and the reply must carry the same one. That, plus a
random source port, is all that stops someone on the path from answering
first with a lie. It is thin, which is why DNSSEC and DNS over HTTPS exist.
