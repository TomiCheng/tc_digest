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
        if line.starts_with("pub struct ")
            || line.starts_with("pub fn ")
            || line.starts_with("pub const fn ")
            || line.starts_with("pub(crate) fn ")
            || line.starts_with("pub(crate) const fn ")
            || line.starts_with("fn round(")
            || line.starts_with("fn absorb_block(")
            || line.starts_with("fn pad(")
            || line.starts_with("fn intermediate_permutation(")
            || line.starts_with("fn pb_permute(")
            || line.starts_with("fn from_initial(")
            || line.starts_with("const fn initial_state(")
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
pub struct Unmarked {}
/// VARIABLE TIME.
#[inline]
pub fn accepted() {}
/// Constant time and variable time.
fn absorb_block() {}
fn pad() {}
/// Constant time.
pub(crate) fn helper() {}
const fn initial_state() {}
fn try_update() {}
/// Constant time with respect to the message.
fn fmt() {}
fn fmt(&self) {}
/// Constant time.
fn drop(&mut self) {}
fn round(state: &mut [u64; 5]) {}
";
    let (checked, missing) = missing_timing_docs(fixture);
    assert_eq!(checked, 11);
    assert_eq!(
        missing,
        [
            "pub struct Unmarked {}",
            "fn absorb_block() {}",
            "fn pad() {}",
            "const fn initial_state() {}",
            "fn fmt(&self) {}",
            "fn round(state: &mut [u64; 5]) {}",
        ]
    );
}

#[test]
fn every_digest_and_crate_visible_helper_has_an_unambiguous_timing_doc() {
    for (name, source) in [
        ("ascon_core.rs", include_str!("../src/ascon_core.rs")),
        ("ascon_cxof128.rs", include_str!("../src/ascon_cxof128.rs")),
        ("ascon_hash256.rs", include_str!("../src/ascon_hash256.rs")),
        ("ascon_legacy.rs", include_str!("../src/ascon_legacy.rs")),
        ("ascon_xof128.rs", include_str!("../src/ascon_xof128.rs")),
        (
            "ascon_xof_legacy.rs",
            include_str!("../src/ascon_xof_legacy.rs"),
        ),
        ("isap.rs", include_str!("../src/isap.rs")),
    ] {
        let (checked, missing) = missing_timing_docs(source);
        assert!(checked > 0, "no declarations scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
