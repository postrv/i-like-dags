import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { offerPinEvent, offerPointerEvent } from "../src/offer.ts";

function cid(label: string): string {
  return createHash("sha256").update(label).digest("hex");
}

test("pointer create is accepted and is idempotent", () => {
  const event = { seq: 1, pointerId: "p", prev: null, new: cid("h") };
  const eventCid = cid("e1");
  assert.deepEqual(
    offerPointerEvent("p", 1, eventCid, event, null, null),
    { ok: "accept" },
  );
  assert.deepEqual(
    offerPointerEvent("p", 1, eventCid, event, eventCid, null),
    { ok: "already_filed" },
  );
  const other = cid("other");
  const refused = offerPointerEvent("p", 1, eventCid, event, other, null);
  assert.equal("err" in refused && refused.err.kind, "divergent");
});

test("pointer update must name the predecessor's head", () => {
  const a = cid("a");
  const b = cid("b");
  const prev = { seq: 1, pointerId: "p", prev: null, new: a };
  const ok = { seq: 2, pointerId: "p", prev: a, new: b };
  const eventCid = cid("e2");
  assert.deepEqual(
    offerPointerEvent("p", 2, eventCid, ok, null, prev),
    { ok: "accept" },
  );
  const forged = { seq: 2, pointerId: "p", prev: cid("nope"), new: b };
  const broken = offerPointerEvent("p", 2, eventCid, forged, null, prev);
  assert.equal("err" in broken && broken.err.kind, "chain_broken");
  const missing = offerPointerEvent("p", 2, eventCid, ok, null, null);
  assert.equal("err" in missing && missing.err.kind, "missing_predecessor");
});

test("pin seq > 1 without prev is refused", () => {
  const event = { seq: 2, pinId: "hold", prev: null };
  const refused = offerPinEvent("hold", 2, cid("deact"), event, null, cid("prev-event"));
  assert.equal("err" in refused && refused.err.kind, "pin_prev_absent");
});

test("pin prev must be the previous event CID", () => {
  const prevEvent = cid("prev-event");
  const event = { seq: 2, pinId: "hold", prev: prevEvent };
  assert.deepEqual(
    offerPinEvent("hold", 2, cid("deact"), event, null, prevEvent),
    { ok: "accept" },
  );
  const broken = offerPinEvent("hold", 2, cid("deact"), event, null, cid("wrong"));
  assert.equal("err" in broken && broken.err.kind, "chain_broken");
});
