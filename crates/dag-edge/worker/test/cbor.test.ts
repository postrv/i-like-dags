import assert from "node:assert/strict";
import { test } from "node:test";
import { CborLimitError, decodeCbor, encodeCbor } from "../src/cbor.ts";
import {
  decodeEntry,
  decodeEntryPayload,
  decodePinEvent,
  decodePinEventEntry,
  decodePointerEvent,
  decodePointerEventEntry,
  encodeEntry,
  encodePointerEvent,
} from "../src/dag.ts";
import { computeCidHex } from "../src/cid.ts";
import { authenticateIngest, ingestAuthConfiguration, tokenMatches } from "../src/auth.ts";
import { inspectBytes } from "../src/inspect.ts";
import { INSPECT_LINK_LIMIT, MAX_CHUNK_SIZE, MAX_ENTRY_LINKS } from "../src/limits.ts";

// Frozen by dag-core's `pointer_entry_encoding_is_frozen_for_edge_interop`.
// Keeping the Rust serializer and the Worker codec on the same bytes prevents
// a locally self-consistent TypeScript encoder/decoder from masking drift.
const RUST_POINTER_PAYLOAD =
  "a563736571016a706f696e7465725f69646c656467652f666978747572656470726576f6636e65779820" +
  "11111111111111111111111111111111111111111111111111111111111111116274731a6553f100";
const RUST_POINTER_ENTRY =
  "a2677061796c6f6164985218a5186318731865187101186a1870186f1869186e187418651872185f18691864" +
  "186c1865186418671865182f18661869187818741875187218651864187018721865187618f61863186e1865" +
  "1877189818201111111111111111111111111111111111111111111111111111111111111111186218741873" +
  "181a1865185318f100656c696e6b7380";
import { checkPinId, checkPointerId } from "../src/ids.ts";

function rustEntryPrefix(declaredLinks: number): Uint8Array {
  return new Uint8Array([
    0xa2,
    0x67, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64,
    0x80,
    0x65, 0x6c, 0x69, 0x6e, 0x6b, 0x73,
    0x9a,
    (declaredLinks >>> 24) & 0xff,
    (declaredLinks >>> 16) & 0xff,
    (declaredLinks >>> 8) & 0xff,
    declaredLinks & 0xff,
  ]);
}

function largeRustEntry(linkCount: number): Uint8Array {
  const prefix = rustEntryPrefix(linkCount);
  const link = new Uint8Array([
    0xa2,
    0x64, 0x6e, 0x61, 0x6d, 0x65,
    0x61, 0x61,
    0x66, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74,
    0x98, 0x20,
    ...new Uint8Array(32),
  ]);
  const bytes = new Uint8Array(prefix.byteLength + link.byteLength * linkCount);
  bytes.set(prefix);
  for (let i = 0; i < linkCount; i++) bytes.set(link, prefix.byteLength + i * link.byteLength);
  return bytes;
}

test("encode/decode map with CID array matches ciborium shape", () => {
  const cid = Array.from({ length: 32 }, (_, i) => i);
  const bytes = encodeCbor({
    seq: 1,
    pointer_id: "p",
    prev: null,
    new: cid,
    ts: 1,
  });
  const back = decodeCbor(bytes) as {
    seq: number;
    pointer_id: string;
    prev: null;
    new: Uint8Array;
    ts: number;
  };
  assert.equal(back.seq, 1);
  assert.equal(back.pointer_id, "p");
  assert.equal(back.prev, null);
  assert.deepEqual(Array.from(back.new), cid);
});

test("pointer event encode then decode", async () => {
  const head = await computeCidHex(new TextEncoder().encode("head"));
  const encoded = encodePointerEvent({
    seq: 1,
    pointerId: "models/fraud-detector/production",
    prev: null,
    new: head,
    ts: 1,
  });
  const event = decodePointerEvent(encoded);
  assert.equal(event.seq, 1);
  assert.equal(event.pointerId, "models/fraud-detector/production");
  assert.equal(event.prev, null);
  assert.equal(event.new, head);
});

test("pointer entry bytes match the frozen Rust ciborium fixture", () => {
  const rustEntry = decodeEntry(Buffer.from(RUST_POINTER_ENTRY, "hex"));
  assert.equal(
    Buffer.from(decodePointerEventEntry(Buffer.from(RUST_POINTER_ENTRY, "hex"))).toString("hex"),
    RUST_POINTER_PAYLOAD,
  );
  assert.equal(Buffer.from(rustEntry.payload).toString("hex"), RUST_POINTER_PAYLOAD);
  const event = decodePointerEvent(rustEntry.payload);
  assert.deepEqual(event, {
    seq: 1,
    pointerId: "edge/fixture",
    prev: null,
    new: "11".repeat(32),
  });

  const workerEntry = encodeEntry(
    encodePointerEvent({
      seq: 1,
      pointerId: "edge/fixture",
      prev: null,
      new: "11".repeat(32),
      ts: 1_700_000_000,
    }),
  );
  assert.equal(Buffer.from(workerEntry).toString("hex"), RUST_POINTER_ENTRY);
});

// Frozen schema-1 pin payload from dag-core (importance is ignored).
const SCHEMA_1_PIN =
  "a963736571016670696e5f696466676f6c64656e66746172676574a1664469726563749820" +
  "07183f18a918ad189b15186f18e718731853181a184a18a4185118c90b186118bb188918ca18dd18b4182318ee18f6186118d7188f" +
  "187a18f8188218516573636f706566476c6f62616c6a696d706f7274616e636518646a657870697265735f6174f665737461746566" +
  "4163746976656274731a6553f10066617574686f7266746573746572";

test("schema-1 pin event still decodes (importance ignored)", () => {
  const bytes = Buffer.from(SCHEMA_1_PIN, "hex");
  assert.equal(
    Buffer.from(decodePinEventEntry(encodeEntry(bytes))).toString("hex"),
    bytes.toString("hex"),
  );
  const event = decodePinEvent(bytes);
  assert.equal(event.seq, 1);
  assert.equal(event.pinId, "golden");
  assert.equal(event.state, "Active");
  assert.equal(event.scope.kind, "global");
  assert.equal(event.target.kind, "direct");
  assert.equal(event.prev, null);
});

test("accepts the frozen Rust-generated pin payload above the pointer 4 KiB cap", async () => {
  // This shape, length, and digest are frozen by dag-core's
  // `large_historical_pin_payload_is_frozen_for_edge_interop` test. It proves
  // the compatibility case comes from Rust's ciborium serializer rather than
  // merely being a self-consistent TypeScript fixture.
  const payload = encodeCbor({
    seq: 1,
    pin_id: "edge-large-fixture",
    target: { Direct: Array(32).fill(0x07) },
    scope: "Global",
    expires_at: null,
    state: "Active",
    ts: 1_700_000_000,
    author: "x".repeat(5_000),
  });
  assert.equal(payload.byteLength, 5_137);
  assert.equal(
    await computeCidHex(payload),
    "2f752304dd6459b1525394185803c477c6ebb7b945882f9d4362be2846b864fe",
  );
  const entry = encodeEntry(payload);
  assert.deepEqual(decodePinEventEntry(entry), payload);
  assert.equal(decodePinEvent(payload).pinId, "edge-large-fixture");
  assert.throws(() => decodePointerEventEntry(entry), /payload exceeds 4096 bytes/);
});

test("token compare is exact", async () => {
  assert.equal(await tokenMatches("secret", "secret"), true);
  assert.equal(await tokenMatches("secret", "Secret"), false);
  assert.equal(await tokenMatches("secret", "secre"), false);
});

test("ingest tokens support scoped rotation and the deprecated alias", async () => {
  const current = "c".repeat(32);
  const previous = "p".repeat(32);
  const legacy = "l".repeat(32);
  assert.equal(
    (await authenticateIngest(`Bearer ${current}`, { INGEST_TOKEN_CURRENT: current })).ok,
    true,
  );
  const rotated = await authenticateIngest(`bearer ${previous}`, {
    INGEST_TOKEN_CURRENT: current,
    INGEST_TOKEN_PREVIOUS: previous,
  });
  assert.equal(rotated.ok && rotated.auth.usedPrevious, true);
  assert.equal((await authenticateIngest(`Bearer ${legacy}`, { DAG_NODE_TOKEN: legacy })).ok, true);
  assert.deepEqual(await authenticateIngest("Bearer short", { INGEST_TOKEN_CURRENT: "short" }), {
    ok: false,
    kind: "weak_configuration",
  });
  assert.deepEqual(ingestAuthConfiguration({ DAG_NODE_TOKEN: legacy }), {
    usable: true,
    productionReady: false,
    kind: "legacy_only",
  });
  assert.deepEqual(ingestAuthConfiguration({ DAG_INGEST_TOKEN_CURRENT: current }), {
    usable: true,
    productionReady: false,
    kind: "legacy_only",
  });
  assert.deepEqual(ingestAuthConfiguration({ INGEST_TOKEN_CURRENT: current }), {
    usable: true,
    productionReady: true,
    kind: "ready",
  });
  assert.deepEqual(
    ingestAuthConfiguration({
      INGEST_TOKEN_CURRENT: current,
      DAG_INGEST_TOKEN_PREVIOUS: legacy,
    }),
    {
      usable: true,
      productionReady: false,
      kind: "legacy_aliases",
    },
  );
  const compatibilityOverlap = await authenticateIngest(`Bearer ${legacy}`, {
    INGEST_TOKEN_CURRENT: current,
    DAG_INGEST_TOKEN_PREVIOUS: legacy,
  });
  assert.equal(
    compatibilityOverlap.ok && compatibilityOverlap.auth.usedPrevious,
    true,
  );
  assert.deepEqual(
    ingestAuthConfiguration({
      INGEST_TOKEN_CURRENT: current,
      INGEST_TOKEN_PREVIOUS: current,
    }),
    {
      usable: false,
      productionReady: false,
      kind: "weak_configuration",
    },
  );
  assert.deepEqual(
    await authenticateIngest(`Bearer ${current}`, {
      INGEST_TOKEN_CURRENT: current,
      INGEST_TOKEN_PREVIOUS: current,
    }),
    { ok: false, kind: "weak_configuration" },
  );
  assert.deepEqual(
    await authenticateIngest(`Bearer ${current}`, {
      INGEST_TOKEN_CURRENT: current,
      DAG_NODE_TOKEN: current,
    }),
    { ok: false, kind: "weak_configuration" },
  );
  assert.equal(
    (await authenticateIngest(`Bearer ${current}`, {
      INGEST_TOKEN_CURRENT: `${"x".repeat(31)}\n`,
    })).ok,
    false,
  );
});

test("ingest tokens use one portable padding-free base64url alphabet", async () => {
  const valid = "A_z-".repeat(8);
  assert.deepEqual(ingestAuthConfiguration({ INGEST_TOKEN_CURRENT: valid }), {
    usable: true,
    productionReady: true,
    kind: "ready",
  });
  for (const invalid of [
    "é".repeat(32),
    ".".repeat(32),
    "=".repeat(32),
    `${"a".repeat(31)}\u0001`,
  ]) {
    assert.deepEqual(ingestAuthConfiguration({ INGEST_TOKEN_CURRENT: invalid }), {
      usable: false,
      productionReady: false,
      kind: "weak_configuration",
    });
    assert.deepEqual(await authenticateIngest(`Bearer ${invalid}`, { INGEST_TOKEN_CURRENT: valid }), {
      ok: false,
      kind: "invalid",
    });
  }
});

test("strict CBOR rejects duplicate, prototype, and invalid UTF-8 map keys", () => {
  assert.throws(() => decodeCbor(Buffer.from("a2617801617802", "hex")), /duplicate key/);
  assert.throws(
    () => decodeCbor(Buffer.from("a1695f5f70726f746f5f5f01", "hex")),
    /forbidden/,
  );
  assert.throws(() => decodeCbor(Buffer.from("a1617861ff", "hex")), /valid UTF-8/);
  assert.equal(decodeCbor(encodeCbor("\ufeffpointer")), "\ufeffpointer");
});

test("strict DAG schemas reject missing and incorrectly typed fields", () => {
  assert.throws(() => decodeEntry(encodeCbor({ payload: [] })), /links/);
  assert.throws(
    () => decodeEntry(encodeCbor({ payload: [], links: [], extension: null })),
    /Entry.*unknown field|expected Entry map/,
  );
  assert.throws(
    () =>
      decodeEntry(
        encodeCbor({
          payload: [],
          links: [
            {
              target: Array.from({ length: 32 }, () => 0),
              extension: null,
            },
          ],
        }),
      ),
    /link.*unknown field|expected link map/,
  );
  assert.throws(
    () =>
      decodeEntry(
        encodeCbor({
          payload: [],
          links: [],
          meta: { content_type: null, extension: null },
        }),
      ),
    /meta.*unknown field|entry meta must be a map/,
  );
  assert.throws(
    () =>
      decodeEntry(
        encodeCbor({
          payload: [],
          links: [{ name: 7, target: Array.from({ length: 32 }, () => 0) }],
        }),
      ),
    /link name/,
  );
  assert.throws(
    () =>
      decodePointerEvent(
        encodeCbor({
          seq: 1,
          pointer_id: "p",
          prev: null,
          new: Array.from({ length: 32 }, () => 0),
        }),
      ),
    /ts/,
  );
});

test("edge identifiers reject JavaScript-only lone surrogates", () => {
  assert.match(checkPointerId("bad\ud800id") ?? "", /well-formed Unicode/);
  assert.match(checkPinId("bad\udc00id") ?? "", /well-formed Unicode/);
});

test("edge identifiers reject terminal and bidi controls while preserving Unicode", () => {
  for (const unsafe of [
    "line\nbreak",
    "escape\u001bid",
    "line\u2028separator",
    "paragraph\u2029separator",
    "bidi\u202eid",
    "isolate\u2066id",
  ]) {
    assert.match(checkPointerId(unsafe) ?? "", /control or format/);
    assert.match(checkPinId(unsafe) ?? "", /control or format/);
  }
  assert.equal(checkPointerId("模型/Δ-release-🚀"), null);
  assert.equal(checkPinId("保留-雪"), null);
  assert.equal(checkPointerId("فارسی\u200cنام"), null);
  assert.equal(checkPinId("क्\u200dष-pin"), null);
  assert.equal(checkPointerId("family/👩\u200d💻"), null);
});

test("large Rust-style Vec<u8> payloads decode compactly past the old 65536 ceiling", () => {
  const payload = new Uint8Array(70_000);
  payload[69_999] = 255;
  const decoded = decodeEntry(encodeEntry(payload));
  assert.equal(decoded.payload.byteLength, payload.byteLength);
  assert.equal(decoded.payload[69_999], 255);
});

test("near-limit Rust Entries validate every link while retaining only the inspection prefix", () => {
  const bytes = largeRustEntry(80_000);
  assert.equal(bytes.byteLength, 3_920_021);
  assert.ok(bytes.byteLength < MAX_CHUNK_SIZE);

  const inspected = inspectBytes("00".repeat(32), bytes);
  assert.equal(inspected.kind, "entry");
  assert.equal(inspected.link_count, 80_000);
  assert.equal(inspected.links.length, INSPECT_LINK_LIMIT);
  assert.equal(inspected.links_truncated, true);
  assert.deepEqual(inspected.links[0], { name: "a", target: "00".repeat(32) });
  assert.equal(decodeEntryPayload(bytes).byteLength, 0);

  const malformedLastLink = bytes.slice();
  malformedLastLink[malformedLastLink.length - 1] = 0xff;
  assert.throws(() => decodeEntryPayload(malformedLastLink), /CID must be 32 bytes/);
});

test("Entry and generic CBOR structural ceilings fail before materialization", () => {
  assert.throws(() => decodeEntry(rustEntryPrefix(MAX_ENTRY_LINKS + 1)), CborLimitError);
  assert.throws(
    () => decodeCbor(new Uint8Array([0x99, 0x10, 0x01, 0xa0])),
    CborLimitError,
  );
});

test("inspect classifies raw bytes and pointer entries", async () => {
  const raw = inspectBytes("ab".repeat(32), new TextEncoder().encode("hello"));
  assert.equal(raw.kind, "bytes");
  assert.equal(raw.preview, "hello");
  assert.deepEqual(raw.links, []);

  const head = await computeCidHex(new TextEncoder().encode("head"));
  const event = encodePointerEvent({
    seq: 1,
    pointerId: "p",
    prev: null,
    new: head,
    ts: 1,
  });
  const entry = encodeEntry(event);
  const cid = await computeCidHex(entry);
  const info = inspectBytes(cid, entry);
  assert.equal(info.kind, "entry");
  assert.equal(info.pointer_event?.pointer_id, "p");
  assert.equal(info.pointer_event?.new, head);
});
