//! Package metadata is what crates.io and rustc embed in the crate.
//! A placeholder author here would ship as the copyright line.

#[test]
fn published_metadata_names_the_copyright_holder() {
    let authors = env!("CARGO_PKG_AUTHORS");
    let license = env!("CARGO_PKG_LICENSE");
    assert!(
        authors.contains("Laurence Avent"),
        "crate authors must name the copyright holder, got {authors:?}"
    );
    assert!(
        !authors.contains("DAG System Contributors"),
        "placeholder authors must not ship, got {authors:?}"
    );
    assert_eq!(license, "Apache-2.0");
}
