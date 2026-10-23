// Standalone verifier for waterruupto timestamp proofs. Generated from
// src/lib/timestamp-proof.ts by `tsx scripts/timestamps.ts build-verifier`; no dependencies.

// <stdin>
import { readFileSync } from "node:fs";

// src/lib/opentimestamps.ts
var HEADER_MAGIC = new Uint8Array([
  0,
  ...new TextEncoder().encode("OpenTimestamps"),
  0,
  0,
  ...new TextEncoder().encode("Proof"),
  0,
  191,
  137,
  226,
  232,
  132,
  232,
  146,
  148
]);
var MAJOR_VERSION = 1;
var MAX_MSG_LENGTH = 4096;
var MAX_DEPTH = 256;
var OP_TAGS = {
  sha1: 2,
  ripemd160: 3,
  sha256: 8,
  keccak256: 103,
  append: 240,
  prepend: 241,
  reverse: 242,
  hexlify: 243
};
var ATTESTATION_TAGS = {
  pending: "83dfe30d2ef90c8e",
  bitcoin: "0588960d73d71901",
  litecoin: "06869a0d73d71b45"
};
function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
function bytesEqual(a, b) {
  return a.length === b.length && a.every((value, i) => value === b[i]);
}
var Reader = class {
  constructor(bytes) {
    this.bytes = bytes;
  }
  pos = 0;
  byte() {
    const value = this.bytes[this.pos];
    if (value === void 0) throw new Error("Truncated OpenTimestamps data");
    this.pos++;
    return value;
  }
  take(length) {
    if (this.pos + length > this.bytes.length) {
      throw new Error("Truncated OpenTimestamps data");
    }
    const out = this.bytes.slice(this.pos, this.pos + length);
    this.pos += length;
    return out;
  }
  varuint() {
    let value = 0;
    let scale = 1;
    for (; ; ) {
      const b = this.byte();
      value += (b & 127) * scale;
      if (!(b & 128)) return value;
      scale *= 128;
      if (scale > 2 ** 49) throw new Error("OpenTimestamps varuint is too large");
    }
  }
  varbytes(max) {
    const length = this.varuint();
    if (length > max) throw new Error("OpenTimestamps field is too long");
    return this.take(length);
  }
  assertEnd() {
    if (this.pos !== this.bytes.length) throw new Error("Trailing bytes in OpenTimestamps data");
  }
};
function readOp(reader, tag) {
  switch (tag) {
    case OP_TAGS.sha1:
      return { kind: "sha1" };
    case OP_TAGS.ripemd160:
      return { kind: "ripemd160" };
    case OP_TAGS.sha256:
      return { kind: "sha256" };
    case OP_TAGS.keccak256:
      return { kind: "keccak256" };
    case OP_TAGS.reverse:
      return { kind: "reverse" };
    case OP_TAGS.hexlify:
      return { kind: "hexlify" };
    case OP_TAGS.append:
      return { kind: "append", arg: reader.varbytes(MAX_MSG_LENGTH) };
    case OP_TAGS.prepend:
      return { kind: "prepend", arg: reader.varbytes(MAX_MSG_LENGTH) };
    default:
      throw new Error(`Unknown OpenTimestamps operation 0x${tag.toString(16)}`);
  }
}
function readAttestation(reader) {
  const tag = reader.take(8);
  const rawPayload = reader.varbytes(8192);
  const payload = new Reader(rawPayload);
  const tagHex = toHex(tag);
  let attestation;
  if (tagHex === ATTESTATION_TAGS.pending) {
    attestation = { kind: "pending", uri: new TextDecoder().decode(payload.varbytes(1e3)) };
  } else if (tagHex === ATTESTATION_TAGS.bitcoin) {
    attestation = { kind: "bitcoin", height: payload.varuint() };
  } else if (tagHex === ATTESTATION_TAGS.litecoin) {
    attestation = { kind: "litecoin", height: payload.varuint() };
  } else {
    return { kind: "unknown", tag, payload: rawPayload };
  }
  payload.assertEnd();
  return attestation;
}
function readTimestamp(reader, depth) {
  if (depth <= 0) throw new Error("OpenTimestamps proof is nested too deeply");
  const timestamp = { attestations: [], ops: [] };
  const readItem = (tag2) => {
    if (tag2 === 0) {
      timestamp.attestations.push(readAttestation(reader));
    } else {
      const op = readOp(reader, tag2);
      timestamp.ops.push({ op, next: readTimestamp(reader, depth - 1) });
    }
  };
  let tag = reader.byte();
  while (tag === 255) {
    readItem(reader.byte());
    tag = reader.byte();
  }
  readItem(tag);
  return timestamp;
}
function parseOtsFile(bytes) {
  const reader = new Reader(bytes);
  if (!bytesEqual(reader.take(HEADER_MAGIC.length), HEADER_MAGIC)) {
    throw new Error("Not an OpenTimestamps proof");
  }
  if (reader.varuint() !== MAJOR_VERSION) {
    throw new Error("Unsupported OpenTimestamps version");
  }
  if (reader.byte() !== OP_TAGS.sha256) {
    throw new Error("Only SHA-256 OpenTimestamps proofs are supported");
  }
  const digest2 = reader.take(32);
  const timestamp = readTimestamp(reader, MAX_DEPTH);
  reader.assertEnd();
  return { digest: digest2, timestamp };
}
async function applyOp(op, msg, hash) {
  let result2;
  switch (op.kind) {
    case "append":
      result2 = concat(msg, op.arg);
      break;
    case "prepend":
      result2 = concat(op.arg, msg);
      break;
    case "sha256":
    case "sha1":
    case "ripemd160":
      result2 = await hash(op.kind, msg);
      break;
    case "reverse":
      result2 = msg.slice().reverse();
      break;
    case "hexlify":
      result2 = new TextEncoder().encode(toHex(msg));
      break;
    case "keccak256":
      throw new Error("keccak256 OpenTimestamps operations are not supported");
  }
  if (result2.length > MAX_MSG_LENGTH) throw new Error("OpenTimestamps message is too long");
  return result2;
}
async function listOtsAttestations(timestamp, msg, hash) {
  const found = timestamp.attestations.map((attestation) => ({
    attestation,
    msg,
    node: timestamp
  }));
  for (const { op, next } of timestamp.ops) {
    found.push(...await listOtsAttestations(next, await applyOp(op, msg, hash), hash));
  }
  return found;
}

// src/lib/rfc3161.ts
function readDer(bytes, offset) {
  const tag = bytes[offset];
  let lengthByte = bytes[offset + 1];
  if (tag === void 0 || lengthByte === void 0) throw new Error("Truncated DER data");
  let pos = offset + 2;
  let length = lengthByte;
  if (lengthByte & 128) {
    const count = lengthByte & 127;
    if (count === 0 || count > 4) throw new Error("Unsupported DER length");
    length = 0;
    for (let i = 0; i < count; i++) {
      lengthByte = bytes[pos++];
      if (lengthByte === void 0) throw new Error("Truncated DER data");
      length = length * 256 + lengthByte;
    }
  }
  const end = pos + length;
  if (end > bytes.length) throw new Error("Truncated DER data");
  return { tag, content: bytes.subarray(pos, end), end };
}
function children(content) {
  const items = [];
  let offset = 0;
  while (offset < content.length) {
    const item = readDer(content, offset);
    items.push(item);
    offset = item.end;
  }
  return items;
}
function expect(item, tag, what) {
  if (item?.tag !== tag) throw new Error(`Malformed RFC 3161 response: ${what}`);
  return item;
}
function parseGeneralizedTime(content) {
  const text = new TextDecoder().decode(content);
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\.\d+)?Z$/.exec(text);
  if (!match) throw new Error(`Unsupported GeneralizedTime ${text}`);
  const [, y, mo, d, h, mi, s, fraction] = match;
  const ms = fraction ? Math.round(Number(fraction) * 1e3) : 0;
  return new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s), ms));
}
function parseTimeStampResponse(bytes) {
  const response = expect(readDer(bytes, 0), 48, "response");
  const [statusInfo, token] = children(response.content);
  const statusInteger = expect(children(expect(statusInfo, 48, "status").content)[0], 2, "status");
  const status = statusInteger.content.reduce((n, b) => n * 256 + b, 0);
  if (status !== 0 && status !== 1 || !token) return { granted: false, status };
  const [, signedDataWrapper] = children(expect(token, 48, "token").content);
  const signedData = expect(
    children(expect(signedDataWrapper, 160, "signed data").content)[0],
    48,
    "signed data"
  );
  const encapsulated = expect(children(signedData.content)[2], 48, "content info");
  const [, eContentWrapper] = children(encapsulated.content);
  const eContent = expect(
    children(expect(eContentWrapper, 160, "content").content)[0],
    4,
    "content"
  );
  const tstInfo = children(expect(readDer(eContent.content, 0), 48, "TSTInfo").content);
  const imprint = children(expect(tstInfo[2], 48, "message imprint").content);
  return {
    granted: true,
    status,
    hashedMessage: Uint8Array.from(expect(imprint[1], 4, "hashed message").content),
    time: parseGeneralizedTime(expect(tstInfo[4], 24, "time").content)
  };
}

// src/lib/timestamp-proof.ts
var TIMESTAMP_BATCH_FORMAT = "waterruupto-timestamp-batch/v1";
var TIMESTAMP_PROOF_FORMAT = "waterruupto-timestamp-proof/v1";
var TIMESTAMP_PUBLIC_KEY_HEX = "c174856b506192d5dcdb5bc3574d5229394373252350e742cd9db5992e6e634b";
var TIMESTAMP_PUBLIC_KEY_ID = "75bed641b4b4ea79";
function toHex2(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function fromHex(hex) {
  if (!/^(?:[0-9a-f]{2})*$/i.test(hex)) throw new Error("Invalid hex string");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function fromBase64(value) {
  return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
}
function canonicalJson(value) {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new Error("Canonical JSON cannot contain non-finite numbers");
    }
    if (value === void 0) throw new Error("Canonical JSON cannot contain undefined");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value).filter(([, v]) => v !== void 0).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0);
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}
function concatBytes(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
async function digest(algorithm, data) {
  return new Uint8Array(await crypto.subtle.digest(algorithm, data));
}
function sha256(data) {
  return digest("SHA-256", data);
}
var webCryptoOtsHash = async (algorithm, data) => {
  if (algorithm === "sha256") return digest("SHA-256", data);
  if (algorithm === "sha1") return digest("SHA-1", data);
  throw new Error("RIPEMD-160 proofs need the OpenTimestamps client to verify");
};
async function computeLeafHash(saltHex, canonical) {
  return toHex2(
    await sha256(
      concatBytes(Uint8Array.of(0), fromHex(saltHex), new TextEncoder().encode(canonical))
    )
  );
}
async function computeMerkleRoot(leafHash, path) {
  let hash = fromHex(leafHash);
  for (const step of path) {
    const sibling = fromHex(step.hash);
    hash = await sha256(
      step.position === "left" ? concatBytes(Uint8Array.of(1), sibling, hash) : concatBytes(Uint8Array.of(1), hash, sibling)
    );
  }
  return toHex2(hash);
}
var fetchBitcoinBlockFromEsplora = async (height) => {
  let lastError;
  for (const base of ["https://mempool.space/api", "https://blockstream.info/api"]) {
    try {
      const hashResponse = await fetch(`${base}/block-height/${height}`);
      if (!hashResponse.ok) throw new Error(`HTTP ${hashResponse.status}`);
      const blockResponse = await fetch(`${base}/block/${(await hashResponse.text()).trim()}`);
      if (!blockResponse.ok) throw new Error(`HTTP ${blockResponse.status}`);
      const block = await blockResponse.json();
      return { merkleRoot: block.merkle_root, time: block.timestamp };
    } catch (error) {
      lastError = error;
    }
  }
  throw new Error(`Could not look up Bitcoin block ${height}`, { cause: lastError });
};
async function verifyEd25519(publicKeyHex, signature, data) {
  const key = await crypto.subtle.importKey(
    "raw",
    fromHex(publicKeyHex),
    { name: "Ed25519" },
    false,
    ["verify"]
  );
  return crypto.subtle.verify(
    { name: "Ed25519" },
    key,
    signature,
    data
  );
}
function message(error) {
  return error instanceof Error ? error.message : String(error);
}
async function verifyTimestampProof(bundle, fetchBitcoinBlock = fetchBitcoinBlockFromEsplora) {
  const checks = [];
  const add = (label, pass, detail) => {
    checks.push({ label, status: pass ? "pass" : "fail", detail });
    return pass;
  };
  const anchorTimes = [];
  if (bundle.format !== TIMESTAMP_PROOF_FORMAT) {
    add("Format", false, `Expected ${TIMESTAMP_PROOF_FORMAT}`);
    return { ok: false, checks, content: null, existedBy: null };
  }
  let content = null;
  try {
    content = JSON.parse(bundle.item.canonical);
    add(
      "Content is canonical",
      canonicalJson(content) === bundle.item.canonical,
      "The revealed JSON is in its single canonical form"
    );
  } catch (error) {
    add("Content is canonical", false, message(error));
  }
  const leafHash = await computeLeafHash(bundle.item.salt, bundle.item.canonical);
  add(
    "Fingerprint",
    leafHash === bundle.leaf.hash,
    `SHA-256(0x00 || salt || content) = ${leafHash}`
  );
  let statement = null;
  try {
    statement = JSON.parse(bundle.batch.statement);
  } catch (error) {
    add("Batch statement", false, message(error));
  }
  if (statement) {
    const root = await computeMerkleRoot(leafHash, bundle.merklePath);
    add(
      "Included in batch",
      root === statement.merkleRoot && statement.format === TIMESTAMP_BATCH_FORMAT,
      `Merkle path leads to root ${root} of batch #${statement.sequence} (${statement.leafCount} items)`
    );
  }
  const statementBytes = new TextEncoder().encode(bundle.batch.statement);
  const statementDigest = toHex2(await sha256(statementBytes));
  add(
    "Batch digest",
    statementDigest === bundle.batch.digest,
    `SHA-256(statement) = ${statementDigest}`
  );
  try {
    const validSignature = await verifyEd25519(
      bundle.publicKey,
      fromBase64(bundle.batch.signature),
      statementBytes
    );
    add(
      "Signature",
      validSignature,
      validSignature ? "Ed25519 signature over the statement is valid" : "Invalid signature"
    );
  } catch (error) {
    add("Signature", false, `Could not verify Ed25519 signature: ${message(error)}`);
  }
  add(
    "Signing key",
    bundle.publicKey === TIMESTAMP_PUBLIC_KEY_HEX,
    bundle.publicKey === TIMESTAMP_PUBLIC_KEY_HEX ? `Matches Srajan's published key ${TIMESTAMP_PUBLIC_KEY_ID}` : "This is not Srajan's published timestamp key"
  );
  if (bundle.batch.opentimestamps) {
    try {
      const file2 = parseOtsFile(fromBase64(bundle.batch.opentimestamps));
      if (!add(
        "Bitcoin proof covers this batch",
        toHex2(file2.digest) === statementDigest,
        "The OpenTimestamps proof is for this batch digest"
      )) {
        throw new Error("OpenTimestamps digest mismatch");
      }
      const attestations = await listOtsAttestations(
        file2.timestamp,
        file2.digest,
        webCryptoOtsHash
      );
      const bitcoin = attestations.flatMap(
        ({ attestation, msg }) => attestation.kind === "bitcoin" ? [{ height: attestation.height, msg }] : []
      ).sort((a, b) => a.height - b.height);
      const confirmed = bitcoin[0];
      if (confirmed) {
        const block = await fetchBitcoinBlock(confirmed.height);
        const expectedRoot = toHex2(fromHex(block.merkleRoot).reverse());
        if (add(
          "Bitcoin",
          toHex2(confirmed.msg) === expectedRoot,
          `Committed in Bitcoin block ${confirmed.height} at ${new Date(block.time * 1e3).toISOString()}`
        )) {
          anchorTimes.push(block.time * 1e3);
        }
      } else {
        checks.push({
          label: "Bitcoin",
          status: "pending",
          detail: "Submitted to OpenTimestamps calendars; waiting for a Bitcoin block"
        });
      }
    } catch (error) {
      if (!checks.some((c) => c.label === "Bitcoin")) add("Bitcoin", false, message(error));
    }
  } else {
    checks.push({ label: "Bitcoin", status: "pending", detail: "Not yet submitted" });
  }
  if (bundle.batch.rfc3161) {
    try {
      const response = parseTimeStampResponse(fromBase64(bundle.batch.rfc3161));
      if (!response.granted) throw new Error(`Authority refused (status ${response.status})`);
      if (add(
        "Timestamp authority",
        toHex2(response.hashedMessage) === statementDigest,
        `${bundle.batch.rfc3161Url ?? "RFC 3161 authority"} recorded this digest at ${response.time.toISOString()}. Check its signature with openssl ts -verify.`
      )) {
        anchorTimes.push(response.time.getTime());
      }
    } catch (error) {
      add("Timestamp authority", false, message(error));
    }
  } else {
    checks.push({ label: "Timestamp authority", status: "pending", detail: "Not yet received" });
  }
  const failed = checks.some((c) => c.status === "fail");
  const existedBy = anchorTimes.length ? new Date(Math.min(...anchorTimes)).toISOString() : null;
  return { ok: !failed && existedBy !== null, checks, content, existedBy };
}

// <stdin>
var file = process.argv[2];
if (!file) {
  console.error("usage: node verify.mjs <proof.json>");
  process.exit(2);
}
var result = await verifyTimestampProof(JSON.parse(readFileSync(file, "utf8")));
for (const check of result.checks) {
  console.log(`${check.status.toUpperCase().padEnd(8)} ${check.label}: ${check.detail}`);
}
console.log("\nContent:", JSON.stringify(result.content, null, 2));
console.log(
  result.ok ? `
VERIFIED: existed by ${result.existedBy}` : "\nNOT VERIFIED (see failed or pending checks above)"
);
process.exitCode = result.ok ? 0 : 1;
