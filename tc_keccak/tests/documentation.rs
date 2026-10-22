//! Every digest type and crate-visible helper documents its timing.

fn missing_timing_docs(source: &str) -> (usize, Vec<String>) {
    let mut docs = String::new();
    let mut attribute_depth = 0_i32;
    let mut checked = 0;
    let mut missing = Vec::new();
    for line in source.lines().map(str::trim) {
        if let Some(comment) = line.strip_prefix("///") {
            docs.push_str(comment);
            docs.push('\n');
            continue;
        }
        if line.starts_with("#[") || attribute_depth > 0 {
            attribute_depth += line.chars().filter(|&c| c == '[').count() as i32;
            attribute_depth -= line.chars().filter(|&c| c == ']').count() as i32;
            continue;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let digest_type = line.strip_prefix("pub struct ").is_some_and(|rest| {
            rest.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                .next()
                .is_some_and(|name| name.ends_with("Digest") || name.ends_with("Hash"))
        });
        if digest_type
            || line.starts_with("pub fn ")
            || line.starts_with("pub const fn ")
            || line.starts_with("pub(crate) fn ")
            || line.starts_with("pub(crate) const fn ")
            || line.starts_with("fn absorb(")
            || line.starts_with("fn squeeze(")
            || line.starts_with("fn pad_and_switch(")
            || line.starts_with("fn init(")
            || line.starts_with("fn finish_block(")
            || line.starts_with("fn wrap_up(")
            || line.starts_with("fn fmt(")
            || line.starts_with("fn drop(")
        {
            checked += 1;
            let docs = docs.to_ascii_lowercase();
            if docs.contains("constant time") == docs.contains("variable time") {
                missing.push(line.to_owned());
            }
        }
        docs.clear();
    }
    (checked, missing)
}

#[test]
fn the_scanner_requires_exactly_one_timing_classification_on_each_declaration() {
    let fixture = "\
/// Constant time.
pub struct SampleDigest {}
pub struct SampleHash {}
/// VARIABLE TIME.
#[inline]
pub fn accepted() {}
/// Constant time and variable time.
fn absorb() {}
fn squeeze() {}
/// Constant time.
pub(crate) fn helper() {}
fn wrap_up() {}
pub struct Parameters {}
fn try_update() {}
/// Constant time with respect to the message.
fn fmt() {}
fn fmt(&self) {}
/// Constant time.
fn drop(&mut self) {}
fn finish_block(&mut self) {}
";
    let (checked, missing) = missing_timing_docs(fixture);
    assert_eq!(checked, 11);
    assert_eq!(
        missing,
        [
            "pub struct SampleHash {}",
            "fn absorb() {}",
            "fn squeeze() {}",
            "fn wrap_up() {}",
            "fn fmt(&self) {}",
            "fn finish_block(&mut self) {}",
        ]
    );
}

#[test]
fn every_digest_and_crate_visible_helper_has_an_unambiguous_timing_doc() {
    for (name, source) in [
        ("cshake.rs", include_str!("../src/cshake.rs")),
        ("keccak.rs", include_str!("../src/keccak.rs")),
        ("parallelhash.rs", include_str!("../src/parallelhash.rs")),
        ("sha3.rs", include_str!("../src/sha3.rs")),
        ("shake.rs", include_str!("../src/shake.rs")),
        ("tuplehash.rs", include_str!("../src/tuplehash.rs")),
        ("xof_utils.rs", include_str!("../src/xof_utils.rs")),
    ] {
        let (checked, missing) = missing_timing_docs(source);
        assert!(checked > 0, "no declarations scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
