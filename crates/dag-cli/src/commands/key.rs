//! `dag key` — signing identities and the trust keyring.
//!
//! Secret keys live in `<data_dir>/keys/*.json`, mode 0600. That directory is
//! node-local secret material: it is never touched by the store, GC, or
//! `dag migrate`, and must not travel with the provenance data. Trust
//! (public keys only) lives in the control database and is granted
//! explicitly with `dag key trust` — there is no PKI behind it.

use std::ffi::OsString;
use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[cfg(unix)]
use rustix::fs::{self as unix_fs, Dir, Mode, OFlags};

use anyhow::{bail, Context, Result};
use clap::{Subcommand, ValueEnum};
use dag_control::Control;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::output::{terminal_text, Format};

/// Key files are currently under 300 bytes. Keeping a small hard ceiling
/// prevents a damaged or hostile local file from turning a signing operation
/// into an unbounded allocation.
const MAX_KEY_FILE_BYTES: u64 = 4 * 1024;
/// `dag key list` sorts entries for deterministic output, so bound the amount
/// of directory state it will materialize too.
const MAX_LOCAL_KEY_ENTRIES: usize = 4_096;
const MAX_KEY_NAME_BYTES: usize = 128;

#[derive(Subcommand, Debug)]
pub enum KeyCmd {
    /// Generate a signing key and store its secret under <data_dir>/keys/
    Generate {
        /// Portable key-file name: 1-128 ASCII letters, digits, '-' or '_'
        #[arg(long)]
        id: String,
        /// Also add the new key's public half to the trust keyring
        #[arg(long)]
        trust: bool,
        /// Purposes the trust grant covers, comma-separated: verify, adopt
        /// (ADR-004). Defaults to verify.
        #[arg(long = "for", value_name = "PURPOSES", requires = "trust")]
        purposes: Option<String>,
    },
    /// List local signing keys and the trust keyring
    List,
    /// Trust a public key (hex), so its signatures verify as trusted
    Trust {
        /// Hex of the 32-byte Ed25519 public key
        #[arg(long)]
        public_key: String,
        /// Purposes the grant covers, comma-separated: verify (signatures
        /// count as trusted), adopt (effect claims may substitute for
        /// execution — ADR-003/ADR-004). Defaults to verify; adoption is
        /// never implied.
        #[arg(long = "for", value_name = "PURPOSES")]
        purposes: Option<String>,
        /// Whose key this is
        #[arg(long)]
        comment: Option<String>,
    },
    /// Remove a key from the trust keyring (signatures degrade to untrusted)
    Untrust {
        /// Key ID (hex SHA-256 of the public key)
        #[arg(long)]
        key_id: String,
    },
    /// Export a public key for an external verifier (PKIX PEM, DER, or hex)
    ///
    /// `dag signatures` gives a verifier the DSSE envelope; this gives it the
    /// key, in the format `cosign`/`openssl` accept. Name a local key with
    /// `--id`, or convert any raw hex with `--public-key`.
    Export {
        /// Name of a local signing key to export the public half of
        #[arg(long, conflicts_with = "public_key")]
        id: Option<String>,
        /// Raw hex public key to convert (needs no local secret)
        #[arg(long, conflicts_with = "id")]
        public_key: Option<String>,
        /// Output format
        #[arg(long, value_enum, default_value_t = ExportFormat::Pem)]
        format: ExportFormat,
    },
}

/// The forms a public key can be exported in.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// PKIX/SubjectPublicKeyInfo PEM — what `cosign` and `openssl` read.
    Pem,
    /// The raw SPKI DER bytes (44 bytes for Ed25519).
    Der,
    /// This system's native form: the 32 raw public-key bytes as hex.
    Hex,
}

/// On-disk secret key format. Local to this CLI; deliberately boring.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    id: String,
    key_id: String,
    public_key: String,
    /// Hex of the 32-byte Ed25519 seed. The secret.
    secret_seed: String,
}

struct LoadedKey {
    signing_key: SigningKey,
    key_id: String,
    public_key: String,
}

fn keys_dir(control: &Control) -> PathBuf {
    control.path().join("keys")
}

fn key_path(control: &Control, id: &str) -> Result<PathBuf> {
    validate_key_name(id)?;
    Ok(keys_dir(control).join(format!("{}.json", id)))
}

fn validate_key_name(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > MAX_KEY_NAME_BYTES
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        bail!(
            "key id must be 1-{} ASCII letters, digits, '-' or '_', got {:?}",
            MAX_KEY_NAME_BYTES,
            id
        );
    }
    Ok(())
}

/// Load a secret key by name.
pub fn load_signing_key(control: &Control, id: &str) -> Result<SigningKey> {
    let path = key_path(control, id)?;
    let Some(directory) = open_keys_directory(control, true)? else {
        return Err(missing_key_error(id, &path));
    };
    let loaded = open_and_validate_key(&directory, id, &path)
        .with_context(|| format!("loading local signing key {:?}", id))?;
    Ok(loaded.signing_key)
}

pub fn handle(control: &Control, cmd: KeyCmd, fmt: Format) -> Result<()> {
    match cmd {
        KeyCmd::Generate {
            id,
            trust,
            purposes,
        } => {
            let path = key_path(control, &id)?;

            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).map_err(|e| anyhow::anyhow!("OS entropy: {}", e))?;
            let key = SigningKey::from_bytes(&seed);
            let public_key = hex::encode(key.verifying_key().as_bytes());
            let key_id = dag_core::signing::key_id(&key.verifying_key());

            let file = KeyFile {
                id: id.clone(),
                key_id: key_id.clone(),
                public_key: public_key.clone(),
                secret_seed: hex::encode(seed),
            };

            ensure_private_keys_dir(control)?;
            write_secret(control, &id, &serde_json::to_vec_pretty(&file)?)?;

            if trust {
                control.signature_log.trust_key(
                    &public_key,
                    Some(id.clone()),
                    &parse_purposes(purposes.as_deref())?,
                )?;
            }

            let out = serde_json::json!({
                "id": id,
                "key_id": key_id,
                "public_key": public_key,
                "path": path.display().to_string(),
                "trusted": trust,
            });
            fmt.emit(out, |o| {
                format!(
                    "generated key {:?}\n  key_id      {}\n  public_key  {}\n  secret at   {}{}",
                    terminal_text(o["id"].as_str().unwrap()),
                    o["key_id"].as_str().unwrap(),
                    o["public_key"].as_str().unwrap(),
                    terminal_text(o["path"].as_str().unwrap()),
                    if trust {
                        "\n  added to the trust keyring"
                    } else {
                        ""
                    }
                )
            })
        }

        KeyCmd::List => {
            let local = list_local_keys(control)?;
            let trusted: Vec<_> = control.signature_log.trusted_keys()?;

            let out = serde_json::json!({ "local": local, "trusted": trusted });
            fmt.emit(out, |o| {
                let mut s = String::from("local signing keys:\n");
                let locals = o["local"].as_array().unwrap();
                if locals.is_empty() {
                    s.push_str("  (none — `dag key generate --id <name>`)\n");
                }
                for k in locals {
                    s.push_str(&format!(
                        "  {}  {}\n",
                        terminal_text(k["id"].as_str().unwrap()),
                        k["key_id"].as_str().unwrap()
                    ));
                }
                s.push_str("\ntrusted keys:\n");
                let trusted = o["trusted"].as_array().unwrap();
                if trusted.is_empty() {
                    s.push_str("  (none — `dag key trust --public-key <hex>`)");
                }
                for k in trusted {
                    // An empty purposes list is a pre-ADR-004 grant, which
                    // means verification only; say so rather than showing
                    // nothing.
                    let purposes = match k["purposes"].as_array() {
                        Some(p) if !p.is_empty() => p
                            .iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(","),
                        _ => "verify (legacy grant)".to_string(),
                    };
                    s.push_str(&format!(
                        "  {}  for {}  {}\n",
                        k["key_id"].as_str().unwrap(),
                        purposes,
                        terminal_text(k["comment"].as_str().unwrap_or("(no comment)"))
                    ));
                }
                s.trim_end().to_string()
            })
        }

        KeyCmd::Trust {
            public_key,
            purposes,
            comment,
        } => {
            let entry = control.signature_log.trust_key(
                &public_key,
                comment,
                &parse_purposes(purposes.as_deref())?,
            )?;
            let out = serde_json::to_value(&entry)?;
            fmt.emit(out, |_| {
                format!(
                    "trusted key {} for {}",
                    entry.key_id,
                    entry.effective_purposes().join(", ")
                )
            })
        }

        KeyCmd::Untrust { key_id } => {
            let existed = control.signature_log.untrust_key(&key_id)?;
            if !existed {
                bail!("key {} was not in the trust keyring", key_id);
            }
            let out = serde_json::json!({ "key_id": key_id, "untrusted": true });
            fmt.emit(out, |_| format!("untrusted key {}", terminal_text(&key_id)))
        }

        KeyCmd::Export {
            id,
            public_key,
            format,
        } => {
            let key = match (id, public_key) {
                (Some(id), None) => load_signing_key(control, &id)?.verifying_key(),
                (None, Some(hex_key)) => dag_core::signing::verifying_key_from_hex(&hex_key)
                    .map_err(|e| anyhow::anyhow!("{}", e))?,
                (None, None) => bail!("give --id <name> or --public-key <hex> to export"),
                // clap `conflicts_with` rules this out.
                (Some(_), Some(_)) => unreachable!("--id and --public-key conflict"),
            };
            match format {
                ExportFormat::Pem => print!("{}", dag_core::signing::public_key_pem(&key)),
                ExportFormat::Der => {
                    use std::io::Write;
                    std::io::stdout()
                        .write_all(&dag_core::signing::public_key_spki_der(&key))
                        .context("writing DER to stdout")?;
                }
                ExportFormat::Hex => println!("{}", hex::encode(key.as_bytes())),
            }
            Ok(())
        }
    }
}

/// Parse a comma-separated `--for` list into typed purposes.
///
/// `None` — the flag not given — is the default grant: verification only.
/// Adoption is never implied (ADR-004).
fn parse_purposes(spec: Option<&str>) -> Result<Vec<dag_control::TrustPurpose>> {
    match spec {
        None => Ok(vec![dag_control::TrustPurpose::Verify]),
        Some(s) => s
            .split(',')
            .map(|p| {
                p.trim()
                    .parse::<dag_control::TrustPurpose>()
                    .map_err(|e| anyhow::anyhow!("{}", e))
            })
            .collect(),
    }
}

/// Create the signing-key directory owner-only on Unix. Secret files are
/// themselves `0600`, but a private directory also hides identity names and
/// prevents another local account from planting replacement paths.
fn ensure_private_keys_dir(control: &Control) -> Result<()> {
    let path = keys_dir(control);
    #[cfg(unix)]
    let created = match std::fs::symlink_metadata(&path) {
        Ok(_) => false,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting {}", path.display()));
        }
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&path)
        .with_context(|| format!("creating signing-key directory {}", path.display()))?;

    // Verify an existing path was not a symlink or special file. On Unix,
    // persist a newly created directory before a later trust grant can become
    // durable.
    let _directory = open_keys_directory(control, false)?
        .expect("a successfully created signing-key directory must exist");
    #[cfg(unix)]
    if created {
        _directory
            .file
            .sync_all()
            .with_context(|| format!("making {} durable", path.display()))?;
        File::open(control.path())
            .and_then(|parent| parent.sync_all())
            .with_context(|| format!("making {} durable", control.path().display()))?;
    }
    Ok(())
}

/// Write a secret file with owner-only permissions and no path traversal.
fn write_secret(control: &Control, id: &str, bytes: &[u8]) -> Result<()> {
    let path = key_path(control, id)?;
    let _directory = open_keys_directory(control, false)?
        .expect("the signing-key directory was created before writing");

    #[cfg(unix)]
    let mut file = {
        let name = key_filename(id);
        let descriptor = match unix_fs::openat(
            &_directory.file,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o600),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::EXIST => {
                bail!(
                    "{} already exists — refusing to overwrite a signing key",
                    path.display()
                )
            }
            Err(error) => {
                return Err(error).with_context(|| format!("creating {}", path.display()));
            }
        };
        File::from(descriptor)
    };

    #[cfg(not(unix))]
    let mut file = {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                bail!(
                    "{} already exists — refusing to overwrite a signing key",
                    path.display()
                )
            }
            Err(error) => {
                return Err(error).with_context(|| format!("creating {}", path.display()));
            }
        }
    };

    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("making {} durable", path.display()))?;

    // Persist the directory entry too. Without this, a successful key
    // generation can disappear after power loss even though its bytes were
    // flushed, leaving a trust grant whose local signing key is gone.
    #[cfg(unix)]
    _directory
        .file
        .sync_all()
        .with_context(|| format!("making {} durable", _directory.path.display()))?;
    Ok(())
}

struct KeysDirectory {
    path: PathBuf,
    #[cfg(unix)]
    file: File,
    metadata: Metadata,
}

/// Open the key directory itself without following a replacement symlink.
fn open_keys_directory(control: &Control, missing_ok: bool) -> Result<Option<KeysDirectory>> {
    let path = keys_dir(control);

    #[cfg(unix)]
    let file = {
        let descriptor = match unix_fs::open(
            &path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if missing_ok && error == rustix::io::Errno::NOENT => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "opening signing-key directory {} without following links",
                        path.display()
                    )
                });
            }
        };
        File::from(descriptor)
    };

    #[cfg(not(unix))]
    let metadata = {
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if missing_ok && error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting {}", path.display()));
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "signing-key path {} must be a real directory, not a link or special file",
                path.display()
            );
        }
        metadata
    };

    #[cfg(unix)]
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting opened directory {}", path.display()))?;
    if !metadata.is_dir() {
        bail!("signing-key path {} is not a directory", path.display());
    }
    validate_directory_permissions(&path, &metadata)?;
    Ok(Some(KeysDirectory {
        path,
        #[cfg(unix)]
        file,
        metadata,
    }))
}

#[cfg(unix)]
fn validate_directory_permissions(path: &Path, metadata: &Metadata) -> Result<()> {
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        bail!(
            "signing-key directory {} is group/world-writable (mode {:04o}); remove those write bits",
            path.display(),
            mode
        );
    }
    if mode & 0o055 != 0 {
        tracing::warn!(
            target: "dag::permissions",
            path = %path.display(),
            mode = format_args!("{:04o}", mode),
            "signing-key directory grants group/world access; use mode 0700 to keep key names private"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_directory_permissions(_path: &Path, _metadata: &Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn key_filename(id: &str) -> OsString {
    OsString::from(format!("{}.json", id))
}

fn missing_key_error(id: &str, path: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "no key {:?} at {}; `dag key generate --id {}`",
        id,
        path.display(),
        id
    )
}

fn open_and_validate_key(directory: &KeysDirectory, id: &str, path: &Path) -> Result<LoadedKey> {
    #[cfg(unix)]
    let name = key_filename(id);

    #[cfg(unix)]
    let file = {
        let descriptor = match unix_fs::openat(
            &directory.file,
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(error) if error == rustix::io::Errno::NOENT => {
                return Err(missing_key_error(id, path));
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("opening {} without following links", path.display())
                });
            }
        };
        File::from(descriptor)
    };

    #[cfg(not(unix))]
    let file = {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(missing_key_error(id, path));
            }
            Err(error) => {
                return Err(error).with_context(|| format!("inspecting {}", path.display()));
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "signing key {} must be a regular file, not a link or special file",
                path.display()
            );
        }
        File::open(path).with_context(|| format!("opening {}", path.display()))?
    };

    read_and_validate_key(file, &directory.metadata, id, path)
}

fn read_and_validate_key(
    mut file: File,
    directory_metadata: &Metadata,
    expected_id: &str,
    path: &Path,
) -> Result<LoadedKey> {
    let before = file
        .metadata()
        .with_context(|| format!("inspecting {}", path.display()))?;
    if !before.is_file() {
        bail!("signing key {} is not a regular file", path.display());
    }
    validate_key_permissions(path, directory_metadata, &before)?;
    if before.len() > MAX_KEY_FILE_BYTES {
        bail!(
            "signing key {} is {} bytes; maximum is {}",
            path.display(),
            before.len(),
            MAX_KEY_FILE_BYTES
        );
    }

    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(MAX_KEY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() as u64 > MAX_KEY_FILE_BYTES {
        bail!(
            "signing key {} exceeds the {}-byte maximum",
            path.display(),
            MAX_KEY_FILE_BYTES
        );
    }
    let after = file
        .metadata()
        .with_context(|| format!("re-inspecting {}", path.display()))?;
    if !same_file_version(&before, &after) {
        bail!(
            "signing key {} changed while it was being read",
            path.display()
        );
    }

    let key_file: KeyFile = serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing key file {}", path.display()))?;
    if key_file.id != expected_id {
        bail!(
            "key file {} declares id {:?}, expected {:?}",
            path.display(),
            key_file.id,
            expected_id
        );
    }
    if key_file.secret_seed.len() != 64 {
        bail!("key file {} seed is not 32 bytes", path.display());
    }
    let mut seed = [0u8; 32];
    hex::decode_to_slice(&key_file.secret_seed, &mut seed)
        .with_context(|| format!("key file {} seed is not hex", path.display()))?;
    let signing_key = SigningKey::from_bytes(&seed);
    let public_key = hex::encode(signing_key.verifying_key().as_bytes());
    let key_id = dag_core::signing::key_id(&signing_key.verifying_key());
    if key_file.public_key != public_key {
        bail!(
            "key file {} public_key does not match its secret seed",
            path.display()
        );
    }
    if key_file.key_id != key_id {
        bail!(
            "key file {} key_id does not match its secret seed",
            path.display()
        );
    }

    Ok(LoadedKey {
        signing_key,
        key_id,
        public_key,
    })
}

#[cfg(unix)]
fn validate_key_permissions(path: &Path, directory: &Metadata, file: &Metadata) -> Result<()> {
    let mode = file.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "signing key {} grants group/world access (mode {:04o}); use mode 0600 or read-only 0400",
            path.display(),
            mode
        );
    }
    if file.uid() != directory.uid() {
        tracing::warn!(
            target: "dag::permissions",
            path = %path.display(),
            file_uid = file.uid(),
            directory_uid = directory.uid(),
            "signing key and its directory have different owners; verify this is an intentional secret mount"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_key_permissions(_path: &Path, _directory: &Metadata, _file: &Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn same_file_version(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_version(before: &Metadata, after: &Metadata) -> bool {
    before.len() == after.len() && before.modified().ok() == after.modified().ok()
}

fn list_local_keys(control: &Control) -> Result<Vec<serde_json::Value>> {
    let Some(directory) = open_keys_directory(control, true)? else {
        return Ok(Vec::new());
    };
    let mut names = list_key_directory_entries(&directory)?;
    names.sort();
    let mut local = Vec::new();
    for name in names {
        let Some(name) = name.to_str() else {
            bail!(
                "signing-key directory {} contains a non-UTF-8 entry",
                directory.path.display()
            );
        };
        let Some(id) = name.strip_suffix(".json") else {
            continue;
        };
        validate_key_name(id).with_context(|| {
            format!(
                "invalid key filename {}",
                directory.path.join(name).display()
            )
        })?;
        let path = directory.path.join(name);
        let loaded = open_and_validate_key(&directory, id, &path)
            .with_context(|| format!("loading local signing key {:?}", id))?;
        local.push(serde_json::json!({
            "id": id,
            "key_id": loaded.key_id,
            "public_key": loaded.public_key,
        }));
    }
    Ok(local)
}

#[cfg(unix)]
fn list_key_directory_entries(directory: &KeysDirectory) -> Result<Vec<OsString>> {
    let duplicate =
        rustix::io::dup(&directory.file).context("duplicating signing-key directory descriptor")?;
    let mut names = Vec::new();
    for entry in Dir::read_from(File::from(duplicate))
        .with_context(|| format!("reading {}", directory.path.display()))?
    {
        let entry = entry.with_context(|| format!("reading {}", directory.path.display()))?;
        let name = OsString::from_vec(entry.file_name().to_bytes().to_vec());
        if name == OsStr::new(".") || name == OsStr::new("..") {
            continue;
        }
        if names.len() >= MAX_LOCAL_KEY_ENTRIES {
            bail!(
                "signing-key directory {} contains more than {} entries",
                directory.path.display(),
                MAX_LOCAL_KEY_ENTRIES
            );
        }
        names.push(name);
    }
    Ok(names)
}

#[cfg(not(unix))]
fn list_key_directory_entries(directory: &KeysDirectory) -> Result<Vec<OsString>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&directory.path)
        .with_context(|| format!("reading {}", directory.path.display()))?
    {
        let entry = entry.with_context(|| format!("reading {}", directory.path.display()))?;
        if names.len() >= MAX_LOCAL_KEY_ENTRIES {
            bail!(
                "signing-key directory {} contains more than {} entries",
                directory.path.display(),
                MAX_LOCAL_KEY_ENTRIES
            );
        }
        names.push(entry.file_name());
    }
    Ok(names)
}
