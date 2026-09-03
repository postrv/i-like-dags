import { readFile } from "node:fs/promises";

const lockfiles = process.argv.slice(2);
if (lockfiles.length === 0) {
  console.error("usage: node scripts/check-npm-lock-policy.mjs <package-lock.json> [...]");
  process.exit(2);
}

const permissiveLicenses = new Set([
  "0BSD",
  "Apache-2.0",
  "Apache-2.0 OR MIT",
  "BSD-3-Clause",
  "CC0-1.0",
  "ISC",
  "MIT",
  "MIT OR Apache-2.0",
]);

function packageName(lockPath) {
  const marker = "node_modules/";
  const offset = lockPath.lastIndexOf(marker);
  return offset === -1 ? lockPath : lockPath.slice(offset + marker.length);
}

function approvedToolingLicense(name, metadata) {
  const license = metadata.license;

  // lightningcss and its platform binaries are build/test tooling only. MPL
  // is file-level copyleft and none of these packages are shipped in the
  // Worker bundle.
  if (
    license === "MPL-2.0" &&
    metadata.dev === true &&
    (name === "lightningcss" || name.startsWith("lightningcss-"))
  ) {
    return true;
  }

  // sharp's prebuilt libvips packages are optional development-tool binaries.
  // Keep the LGPL allowance scoped to those exact package families rather
  // than accepting it for arbitrary runtime dependencies.
  const sharpLicenses = new Set([
    "LGPL-3.0-or-later",
    "Apache-2.0 AND LGPL-3.0-or-later",
    "Apache-2.0 AND LGPL-3.0-or-later AND MIT",
  ]);
  return (
    sharpLicenses.has(license) &&
    metadata.dev === true &&
    metadata.optional === true &&
    (name.startsWith("@img/sharp-libvips-") ||
      name.startsWith("@img/sharp-win32-") ||
      name === "@img/sharp-wasm32")
  );
}

const failures = [];
let packageCount = 0;

for (const lockfile of lockfiles) {
  let lock;
  try {
    lock = JSON.parse(await readFile(lockfile, "utf8"));
  } catch (error) {
    failures.push(`${lockfile}: cannot read a valid JSON lockfile: ${error.message}`);
    continue;
  }

  if (lock.lockfileVersion !== 3 || typeof lock.packages !== "object") {
    failures.push(`${lockfile}: require npm package-lock v3 with a packages map`);
    continue;
  }

  for (const [lockPath, metadata] of Object.entries(lock.packages)) {
    if (lockPath === "") continue;
    packageCount += 1;
    const name = packageName(lockPath);

    if (
      typeof metadata.resolved !== "string" ||
      !metadata.resolved.startsWith("https://registry.npmjs.org/")
    ) {
      failures.push(`${lockfile}: ${name} has an unapproved source ${metadata.resolved ?? "<missing>"}`);
    }
    if (typeof metadata.integrity !== "string" || !metadata.integrity.startsWith("sha512-")) {
      failures.push(`${lockfile}: ${name} has no sha512 lockfile integrity`);
    }
    if (
      typeof metadata.license !== "string" ||
      (!permissiveLicenses.has(metadata.license) &&
        !approvedToolingLicense(name, metadata))
    ) {
      failures.push(`${lockfile}: ${name} has unapproved license ${metadata.license ?? "<missing>"}`);
    }
  }
}

if (failures.length > 0) {
  for (const failure of failures) console.error(failure);
  process.exit(1);
}

console.log(`npm lock policy ok: ${lockfiles.length} lockfile(s), ${packageCount} package(s)`);
