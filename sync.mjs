// Mirrors https://waterruup.to/api/timestamps/batches into batches/<sequence>/.
// Append-only: refuses batches that are unsigned, break the digest chain, or would
// rewrite an already published statement, signature or RFC 3161 token.
//
//   node sync.mjs                         fetch from the site
//   node sync.mjs --from-file batches.json

import {createHash, createPublicKey, verify} from "node:crypto";
import {existsSync, mkdirSync, readFileSync, writeFileSync} from "node:fs";

const SOURCE = "https://waterruup.to/api/timestamps/batches";
const publicKey = createPublicKey(readFileSync("public-key.pem"));

async function loadBatches() {
    const fileIndex = process.argv.indexOf("--from-file");
    if (fileIndex !== -1) return JSON.parse(readFileSync(process.argv[fileIndex + 1], "utf8"));
    const response = await fetch(SOURCE);
    if (!response.ok) throw new Error(`${SOURCE} returned HTTP ${response.status}`);
    return response.json();
}

function writeOnce(file, bytes) {
    if (existsSync(file)) {
        if (!readFileSync(file).equals(bytes)) throw new Error(`Refusing to rewrite ${file}`);
        return;
    }
    writeFileSync(file, bytes);
}

const batches = (await loadBatches()).sort((a, b) => a.sequence - b.sequence);
let previousDigest = null;
for (const batch of batches) {
    const statement = Buffer.from(batch.statement, "utf8");
    const parsed = JSON.parse(batch.statement);
    const digest = createHash("sha256").update(statement).digest("hex");
    if (digest !== batch.digest) throw new Error(`Batch ${batch.sequence}: digest mismatch`);
    if (parsed.sequence !== batch.sequence) throw new Error(`Batch ${batch.sequence}: wrong sequence`);
    if (parsed.previousDigest !== previousDigest) {
        throw new Error(`Batch ${batch.sequence}: does not chain to the previous batch`);
    }
    const signature = Buffer.from(batch.signature, "base64");
    if (!verify(null, statement, publicKey, signature)) {
        throw new Error(`Batch ${batch.sequence}: invalid signature`);
    }
    previousDigest = digest;

    const dir = `batches/${String(batch.sequence).padStart(6, "0")}`;
    mkdirSync(dir, {recursive: true});
    writeOnce(`${dir}/statement.json`, statement);
    writeOnce(`${dir}/statement.json.sig`, signature);
    if (batch.rfc3161) writeOnce(`${dir}/statement.json.tsr`, Buffer.from(batch.rfc3161, "base64"));
    // OpenTimestamps proofs grow once Bitcoin confirms them, so they may be replaced.
    if (batch.opentimestamps) {
        writeFileSync(`${dir}/statement.json.ots`, Buffer.from(batch.opentimestamps, "base64"));
    }
    const summary = {
        sequence: batch.sequence,
        sealedAt: batch.sealedAt,
        leafCount: batch.leafCount,
        digest,
        bitcoinBlockHeight: batch.bitcoinBlockHeight,
        bitcoinBlockTime: batch.bitcoinBlockTime,
        rfc3161Url: batch.rfc3161Url,
        rfc3161Time: batch.rfc3161Time,
    };
    writeFileSync(`${dir}/batch.json`, JSON.stringify(summary, null, 2) + "\n");
}
console.log(`Synced ${batches.length} batches`);
