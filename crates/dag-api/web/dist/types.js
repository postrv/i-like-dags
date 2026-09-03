/**
 * Wire types for the dag HTTP API.
 *
 * These mirror the `serde` structs in `crates/dag-api/src/routes/`. Keeping
 * them in one place means a change to a Rust response shape shows up as a
 * type error at the call site rather than as `undefined` on screen.
 */
/** The four filterable event streams. */
export const EVENT_KINDS = ['pointer', 'pin', 'job', 'storage'];
/** Which stream an event belongs to. */
export function kindOf(event) {
    switch (event.type) {
        case 'PointerUpdate': return 'pointer';
        case 'PinEvent': return 'pin';
        case 'JobRun': return 'job';
        case 'StorageHealth': return 'storage';
    }
}
/** Flatten a `RunStatus` to its variant name. */
export function statusName(status) {
    return typeof status === 'string' ? status : 'Failed';
}
