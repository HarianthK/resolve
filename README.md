# Resolve

A DNS resolver written from the packet up, in one Python file with no
dependencies. It does what your operating system's resolver hides from you:
starts at a root server, follows each referral down, and prints the answer.

    $ python resolve.py en.wikipedia.org -v
      192.203.230.10   en.wikipedia.org A -> 0 answers, 6 authority, 12 glue
      199.249.112.1    en.wikipedia.org A -> 0 answers, 3 authority, 6 glue
      208.80.154.238   en.wikipedia.org A -> 1 answers, 0 authority, 0 glue
      en.wikipedia.org is an alias for dyna.wikimedia.org
      199.249.120.1    dyna.wikimedia.org A -> 0 answers, 3 authority, 6 glue
      208.80.153.231   dyna.wikimedia.org A -> 1 answers, 0 authority, 0 glue
    dyna.wikimedia.org	180	A	198.35.26.224

Three hops: a root server says "ask the .org servers", an .org server says
"ask wikimedia's servers", and one of those answers. The answer is an alias,
so it goes again, this time starting from the .org server it already knows.

## What it handles

- A, AAAA, NS, CNAME, MX and TXT records, decoded from their wire form.
- Name compression, the pointers that let a reply say "same name as byte 12".
- Referrals with glue (the name servers' addresses come along) and without
  (the name server's own name has to be resolved first, from scratch).
- CNAME chains, and NXDOMAIN when a name does not exist.
- Truncation: a reply over 512 bytes arrives cut off with a flag set, and the
  same question is asked again over TCP.
- A cache that keeps every answer and referral for exactly as long as its TTL
  allows, so asking twice sends no packets the second time, and remembers
  names that do not exist for as long as their zone's SOA record says.

## Why

I wanted to know what actually happens between typing a name and getting an
address, and the only way to know is to send the packets yourself. It took
one afternoon. [DOCS.md](DOCS.md) is what I learned.

## Running it

    python resolve.py NAME [A|AAAA|NS|MX|TXT] [-v]
    python test_resolve.py

The test parses a packet built by hand, breaks on any parsing mistake, checks
the cache against a scripted network that counts every packet while a fake
clock jumps forward, and then checks one live answer against the system
resolver.
