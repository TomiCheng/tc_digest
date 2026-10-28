//! Every digest type and helper function documents its timing.

// Methods of the digest traits, documented on the traits themselves.
const TRAIT_METHODS: &[&str] = &[
    "fn default(",
    "fn digest_size(",
    "fn byte_length(",
    "fn try_update(",
    "fn try_do_final(",
    "fn try_reset(",
    "fn try_output(",
    "fn try_output_final(",
];

fn missing_timing_docs(source: &str) -> (usize, Vec<String>) {
    let mut docs = String::new();
    let mut attribute_depth = 0_i32;
    let mut checked = 0;
    let mut missing = Vec::new();
    for line in source.lines().map(str::trim) {
        if line == "mod tests {" {
            break;
        }
        // Lines are joined with a space, so a wrapped "constant time" still counts.
        if let Some(comment) = line.strip_prefix("///") {
            docs.push_str(comment.trim());
            docs.push(' ');
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
        let declaration = ["pub struct ", "pub fn ", "pub const fn ", "pub(crate) fn "]
            .iter()
            .chain(&["pub(super) unsafe fn ", "unsafe fn ", "const fn ", "fn "])
            .any(|prefix| line.starts_with(prefix));
        let trait_method = TRAIT_METHODS.iter().any(|name| line.starts_with(name));
        if declaration && !trait_method {
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
fn helper() {}
/// Constant
/// time when wrapped.
fn wrapped() {}
fn undocumented() {}
/// Constant time.
#[target_feature(enable = \"avx2\")]
unsafe fn vector() {}
pub(super) unsafe fn compress() {}
fn try_update() {}
fn default() -> Self {}
/// Constant time.
fn drop(&mut self) {}
mod tests {
fn ignored() {}
";
    let (checked, missing) = missing_timing_docs(fixture);
    assert_eq!(checked, 9);
    assert_eq!(
        missing,
        [
            "pub struct Unmarked {}",
            "fn helper() {}",
            "fn undocumented() {}",
            "pub(super) unsafe fn compress() {}",
        ]
    );
}

#[test]
fn every_digest_and_helper_has_an_unambiguous_timing_doc() {
    for (name, source) in [
        ("blake2b.rs", include_str!("../src/blake2b.rs")),
        ("blake2s.rs", include_str!("../src/blake2s.rs")),
        ("blake2xs.rs", include_str!("../src/blake2xs.rs")),
        ("blake3.rs", include_str!("../src/blake3.rs")),
        (
            "blake3_portable.rs",
            include_str!("../src/blake3_portable.rs"),
        ),
        (
            "blake3_upstream.rs",
            include_str!("../src/blake3_upstream.rs"),
        ),
    ] {
        let (checked, missing) = missing_timing_docs(source);
        assert!(checked > 0, "no declarations scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
