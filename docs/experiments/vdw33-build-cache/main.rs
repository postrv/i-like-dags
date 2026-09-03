//! vdw33-exp: the effect-key experiment from docs/PROOF_ARTIFACTS.md.
//!
//! Drives one exec job per Lean shard module through dag-control/dag-jobs,
//! with the transitive import closure as pointer inputs, so the effect cache
//! provides build-cache semantics. Prints one JSON line per executed module
//! and a final summary line.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use dag_control::{AttestedEffects, Control, EffectAttester, EffectCache, EffectClaimSink};
use dag_core::{ContentStore, Determinism, EffectKey, JobId, JobInput, JobPolicy, JobSpec};
use dag_jobs::exec::ExecConfig;
use dag_jobs::{execute_once_hooked, resolve_inputs, Capabilities, EffectHooks};
use ed25519_dalek::SigningKey;

/// Deterministic demo builder key (this is an experiment harness, not an
/// operational deployment: a fixed seed makes runs reproducible).
const BUILDER_SEED: [u8; 32] = [13u8; 32];

const LEAN: &str = "/Users/laurence/.elan/toolchains/leanprover--lean4---v4.10.0/bin/lean";
const TOOLCHAIN: &str = "leanprover/lean4:v4.10.0";

struct Args {
    data_dir: PathBuf,
    pkg: PathBuf,
    jobs: usize,
    only: Option<HashSet<String>>,
    attest: bool,
    adopt: bool,
}

fn parse_args() -> Args {
    let mut data_dir = None;
    let mut pkg = None;
    let mut jobs = 8usize;
    let mut only = None;
    let mut attest = false;
    let mut adopt = false;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--data-dir" => data_dir = Some(PathBuf::from(args.next().expect("--data-dir value"))),
            "--pkg" => pkg = Some(PathBuf::from(args.next().expect("--pkg value"))),
            "--jobs" => jobs = args.next().expect("--jobs value").parse().expect("jobs"),
            "--attest" => attest = true,
            "--adopt" => adopt = true,
            "--only" => {
                only = Some(
                    args.next()
                        .expect("--only value")
                        .split(',')
                        .map(String::from)
                        .collect::<HashSet<_>>(),
                )
            }
            other => panic!("unknown argument {other:?}"),
        }
    }
    Args {
        data_dir: data_dir.expect("--data-dir is required"),
        pkg: pkg.expect("--pkg is required"),
        jobs,
        only,
        attest,
        adopt,
    }
}

/// module -> direct imports, from `import X` lines.
fn parse_imports(pkg: &PathBuf) -> BTreeMap<String, Vec<String>> {
    let mut imports = BTreeMap::new();
    for entry in std::fs::read_dir(pkg).expect("reading lean_pkg") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("lean") {
            continue;
        }
        let module = path.file_stem().unwrap().to_str().unwrap().to_string();
        let text = std::fs::read_to_string(&path).expect("reading module");
        let deps: Vec<String> = text
            .lines()
            .take_while(|l| l.starts_with("import ") || l.trim().is_empty())
            .filter_map(|l| l.strip_prefix("import "))
            .map(|m| m.trim().to_string())
            .collect();
        imports.insert(module, deps);
    }
    imports
}

/// Transitive closure of imports per module, memoized.
fn closures(imports: &BTreeMap<String, Vec<String>>) -> HashMap<String, Vec<String>> {
    fn visit(
        m: &str,
        imports: &BTreeMap<String, Vec<String>>,
        memo: &mut HashMap<String, Vec<String>>,
    ) -> Vec<String> {
        if let Some(c) = memo.get(m) {
            return c.clone();
        }
        let mut set: HashSet<String> = HashSet::new();
        for dep in imports.get(m).into_iter().flatten() {
            set.insert(dep.clone());
            set.extend(visit(dep, imports, memo));
        }
        let mut v: Vec<String> = set.into_iter().collect();
        v.sort();
        memo.insert(m.to_string(), v.clone());
        v
    }
    let mut memo = HashMap::new();
    for m in imports.keys() {
        visit(m, imports, &mut memo);
    }
    memo
}

/// Level = 1 + max(level of direct imports); leaves are level 0.
fn levels(imports: &BTreeMap<String, Vec<String>>) -> HashMap<String, usize> {
    fn visit(
        m: &str,
        imports: &BTreeMap<String, Vec<String>>,
        memo: &mut HashMap<String, usize>,
    ) -> usize {
        if let Some(&l) = memo.get(m) {
            return l;
        }
        let l = imports
            .get(m)
            .into_iter()
            .flatten()
            .map(|d| visit(d, imports, memo) + 1)
            .max()
            .unwrap_or(0);
        memo.insert(m.to_string(), l);
        l
    }
    let mut memo = HashMap::new();
    for m in imports.keys() {
        visit(m, imports, &mut memo);
    }
    memo
}

fn exec_config(module: &str) -> serde_json::Value {
    let script = format!(
        r#"set -eu
mkdir -p deps
for f in inputs/olean~*; do
  [ -e "$f" ] || continue
  b=${{f#inputs/olean~}}
  cp "$f" "deps/$b.olean"
done
LEAN_PATH="$PWD/deps" {LEAN} -o "outputs/{module}.olean" "inputs/src~{module}""#
    );
    serde_json::json!({
        "command": "/bin/sh",
        "args": ["-c", script],
        "env": { "LEAN_TOOLCHAIN": TOOLCHAIN },
        "outputs": { "olean": format!("outputs/{module}.olean") },
        "timeout_secs": 3600,
    })
}

/// Create-or-update a pointer to `cid`; skip the no-op update so unchanged
/// artifacts keep their sequence numbers (and dependants their cache keys).
fn ensure_pointer(control: &Control, id: &str, cid: dag_core::Cid) -> bool {
    match control.pointer_log.resolve(id) {
        Ok(current) if current == cid => false,
        Ok(_) => {
            control.pointer_log.update(id, cid).expect("pointer update");
            true
        }
        Err(_) => {
            control.pointer_log.create(id, cid).expect("pointer create");
            true
        }
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let Args {
        data_dir,
        pkg,
        jobs,
        only,
        attest,
        adopt,
    } = parse_args();
    let wall = Instant::now();

    let signer = SigningKey::from_bytes(&BUILDER_SEED);
    if attest {
        eprintln!(
            "attesting with builder key {}",
            hex::encode(signer.verifying_key().as_bytes())
        );
    }

    let imports = parse_imports(&pkg);
    let closure = closures(&imports);
    let level = levels(&imports);
    eprintln!(
        "modules: {}, max level: {}",
        imports.len(),
        level.values().max().unwrap()
    );

    let control = Arc::new(Control::open(&data_dir).expect("opening data dir"));

    // Ingest every source and ensure its src/<module> pointer and job exist.
    let mut src_changed = 0usize;
    for module in imports.keys() {
        let bytes = std::fs::read(pkg.join(format!("{module}.lean"))).expect("reading source");
        let cid = control.store.put_chunk(&bytes, None).expect("put source");
        if ensure_pointer(&control, &format!("src/{module}"), cid) {
            src_changed += 1;
        }

        let job_id = JobId::from(format!("vdw33/{module}"));
        if control.job_log.get_job(&job_id).expect("get_job").is_none() {
            let mut pointer_inputs = vec![format!("src/{module}")];
            pointer_inputs.extend(closure[module].iter().map(|d| format!("olean/{d}")));
            let spec = JobSpec {
                job_id: job_id.clone(),
                placement: None,
                inputs: JobInput {
                    static_inputs: vec![],
                    pointer_inputs,
                },
                determinism: Determinism::SideEffecting,
                declared_outputs: vec!["olean".into()],
                code_ref: "exec".into(),
                policy: JobPolicy::default(),
                config: Some(exec_config(module)),
            };
            control.create_job(spec).expect("create_job");
        }
    }
    eprintln!("ingest done: {src_changed} source pointer(s) changed");

    // Execute in level order; within a level, bounded concurrency.
    let max_level = *level.values().max().unwrap();
    let semaphore = Arc::new(tokio::sync::Semaphore::new(jobs));
    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut hits = 0usize;
    let mut misses = 0usize;
    let mut adopted = 0usize;
    let mut exec_ms_total = 0u128;

    for l in 0..=max_level {
        let mut batch: Vec<String> = imports
            .keys()
            .filter(|m| level[*m] == l)
            .filter(|m| only.as_ref().is_none_or(|o| o.contains(*m)))
            .cloned()
            .collect();
        batch.sort();
        if batch.is_empty() {
            continue;
        }

        let mut handles = Vec::new();
        for module in batch {
            let control = control.clone();
            let semaphore = semaphore.clone();
            let signer = signer.clone();
            handles.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let job_id = JobId::from(format!("vdw33/{module}"));

                // Probe the effect cache with the key the runner will use, so
                // the report can say hit/miss exactly rather than by timing.
                let head = control.job_log.get_job(&job_id).unwrap().unwrap();
                let manifest = resolve_inputs(&control, &job_id).expect("resolve");
                let config: ExecConfig =
                    serde_json::from_value(head.spec.config.clone().unwrap()).unwrap();
                let effect_spec = serde_json::to_string(&config).unwrap();
                let key = EffectKey::new(job_id.clone(), manifest.compute_hash(), effect_spec);
                let cached = control.job_log.get(&key).expect("cache probe").is_some();
                // On a miss, probe whether a trusted claim would satisfy it —
                // read-only, so the report can name the source exactly.
                let adoptable =
                    !cached && adopt && control.adopt_attested(&key).expect("probe").is_some();

                let attester = attest.then(|| EffectAttester::new(&control, signer));
                let hooks = EffectHooks {
                    adopt: adopt.then_some(&*control as &dyn AttestedEffects),
                    attest: attester.as_ref().map(|a| a as &dyn EffectClaimSink),
                };

                let t0 = Instant::now();
                let outcome =
                    execute_once_hooked(&control, &job_id, Capabilities::none().with_exec(), hooks)
                        .await
                        .unwrap_or_else(|e| panic!("job {job_id} failed: {e}"));
                let ms = t0.elapsed().as_millis();

                let source = if cached {
                    "cache"
                } else if adoptable {
                    "adopted"
                } else {
                    "executed"
                };
                let olean = outcome
                    .outputs
                    .iter()
                    .find(|(n, _)| n == "olean")
                    .map(|(_, c)| c.clone())
                    .expect("olean output");
                let changed = ensure_pointer(&control, &format!("olean/{module}"), olean.clone());
                (
                    module,
                    source,
                    ms,
                    olean.to_hex()[..12].to_string(),
                    changed,
                )
            }));
        }

        for h in handles {
            let (module, source, ms, olean, changed) = h.await.expect("task");
            match source {
                "cache" => hits += 1,
                "adopted" => adopted += 1,
                _ => misses += 1,
            }
            exec_ms_total += ms;
            let line = serde_json::json!({
                "module": module, "level": l, "source": source, "ms": ms,
                "olean": olean, "olean_changed": changed,
            });
            println!("{line}");
            results.push(line);
        }
    }

    let summary = serde_json::json!({
        "summary": {
            "jobs_run": results.len(),
            "cache_hits": hits,
            "adopted": adopted,
            "executed": misses,
            "exec_ms_sum": exec_ms_total,
            "wall_ms": wall.elapsed().as_millis(),
            "concurrency": jobs,
        }
    });
    println!("{summary}");
}
