//! Human output must make terminal controls visible without rewriting the
//! same fields in JSON output.

use assert_cmd::Command;
use tempfile::tempdir;

fn dag(data_dir: &std::path::Path) -> Command {
    let mut command = Command::cargo_bin("dag").unwrap();
    command.arg("--data-dir").arg(data_dir);
    command
}

#[test]
fn link_names_are_terminal_safe_in_text_and_exact_in_json() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("dag");

    let target = dag(&data_dir)
        .args(["put", "--json", "--data", "target"])
        .output()
        .unwrap();
    assert!(target.status.success());
    let target: serde_json::Value = serde_json::from_slice(&target.stdout).unwrap();
    let target = target["cid"].as_str().unwrap();

    // Join controls are legitimate shaping characters and must remain
    // visible. The rest can manipulate terminal layout or direction.
    let name = "می\u{200c}خواهم/क्\u{200d}ष\nforged\u{1b}[31m\u{85}\u{2028}\u{202e}txt";
    let link = format!("{target}:{name}");
    let entry = dag(&data_dir)
        .args(["put-entry", "--json", "--link"])
        .arg(&link)
        .output()
        .unwrap();
    assert!(
        entry.status.success(),
        "put-entry failed: {}",
        String::from_utf8_lossy(&entry.stderr)
    );
    let entry: serde_json::Value = serde_json::from_slice(&entry.stdout).unwrap();
    let entry = entry["cid"].as_str().unwrap();

    let human = dag(&data_dir)
        .args(["get-links", "--cid", entry])
        .output()
        .unwrap();
    assert!(human.status.success());
    let human = String::from_utf8(human.stdout).unwrap();
    assert_eq!(human.lines().count(), 1, "stored newline changed layout");
    for unsafe_character in ['\n', '\u{1b}', '\u{85}', '\u{2028}', '\u{202e}'] {
        assert!(
            !human.trim_end_matches('\n').contains(unsafe_character),
            "unsafe character U+{:04X} reached human output",
            unsafe_character as u32
        );
    }
    for visible_escape in [r"\n", r"\u{1b}", r"\u{85}", r"\u{2028}", r"\u{202e}"] {
        assert!(human.contains(visible_escape), "missing {visible_escape:?}");
    }
    assert!(human.contains('\u{200c}'));
    assert!(human.contains('\u{200d}'));

    let json = dag(&data_dir)
        .args(["get-links", "--json", "--cid", entry])
        .output()
        .unwrap();
    assert!(json.status.success());
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(json[0]["name"], name, "JSON field semantics changed");
}
