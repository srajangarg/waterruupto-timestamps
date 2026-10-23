# waterruupto timestamps

Public, append-only record of daily timestamp batches from
[waterruup.to](https://waterruup.to). Each batch commits to every note, voice recording,
AI chat message and photo that was new or edited on the site that day, private or public,
without revealing any of them.

Anyone holding an item's proof file can show that the exact content existed **no later
than** the batch's anchored time, and that it was signed by the key below. A proof cannot
show that something was _not_ written earlier.

## How it works

1. Each item version becomes a leaf: `SHA-256(0x00 || 32-byte random salt || canonical JSON)`.
   The salt keeps the leaf from revealing anything, even short or guessable content.
2. Once a day the new leaves are combined into a Merkle tree
   (`SHA-256(0x01 || left || right)`, RFC 6962 shape).
3. `statement.json` records the tree root, item count, time and the digest of the previous
   batch, so batches form a chain. It is signed with the Ed25519 key below.
4. `SHA-256(statement.json)` is anchored in Bitcoin with
   [OpenTimestamps](https://opentimestamps.org) and timestamped by
   [FreeTSA](https://freetsa.org) (RFC 3161).
5. A GitHub Action in this repository mirrors new batches from the site every six hours.
   It refuses unsigned batches, chain breaks and rewrites of published files; only
   `.ots` files change, when Bitcoin confirms them.

## Layout

```
public-key.pem                     Ed25519 signing key (id 75bed641b4b4ea79)
batches/000001/statement.json      signed batch statement
batches/000001/statement.json.sig  raw Ed25519 signature over statement.json
batches/000001/statement.json.ots  OpenTimestamps proof (Bitcoin)
batches/000001/statement.json.tsr  RFC 3161 response from FreeTSA
batches/000001/batch.json          convenience summary
freetsa/                           FreeTSA CA and TSA certificates
verify.mjs                         standalone item-proof verifier (Node 20+, no dependencies)
```

## Verify a batch with standard tools

```bash
cd batches/000001
ots verify statement.json.ots                       # pip install opentimestamps-client
openssl ts -verify -data statement.json -in statement.json.tsr \
    -CAfile ../../freetsa/cacert.pem -untrusted ../../freetsa/tsa.crt
openssl pkeyutl -verify -pubin -inkey ../../public-key.pem -rawin \
    -in statement.json -sigfile statement.json.sig
```

You can also drop `statement.json.ots` together with `statement.json` on
[opentimestamps.org](https://opentimestamps.org).

## Verify an item

Item proofs are JSON files downloaded from an item's page on waterruup.to. They contain
the revealed content, its salt, the Merkle path to its batch, and the batch's statement,
signature and anchor proofs.

```bash
node verify.mjs proof.json
```

The checks recompute the leaf, Merkle root, statement digest and signature, then compare
the OpenTimestamps commitment against the Bitcoin block header from mempool.space or
blockstream.info. The same verifier runs in the browser at
[waterruup.to/verify](https://waterruup.to/verify). Compare a proof's batch statement with
the copy in this repository to confirm the batch was published when it claims.
