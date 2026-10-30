//! Every digest type and crate-visible helper documents its timing. The
//! scan reads every module, whatever features are enabled.

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
                .is_some_and(|name| name.ends_with("Digest"))
        });
        if digest_type
            || line.starts_with("pub enum ")
            || line.starts_with("pub fn ")
            || line.starts_with("pub const fn ")
            || line.starts_with("pub(crate) fn ")
            || line.starts_with("pub(crate) const fn ")
            || line.starts_with("fn compress(")
            || line.starts_with("fn process_")
            || line.starts_with("fn round(")
            || line.starts_with("fn pass(")
            || line.starts_with("fn key_schedule(")
            || line.starts_with("fn mul_x(")
            || line.starts_with("const fn mul_x(")
            || line.starts_with("const fn generate_")
            || line.starts_with("fn transform(")
            || line.starts_with("fn length_field(")
            || line.starts_with("fn up(")
            || line.starts_with("fn down(")
            || line.starts_with("fn photon_permutation(")
            || line.starts_with("fn xor_into(")
            || line.starts_with("fn finish_absorbing(")
            || line.starts_with("fn sparkle_opt")
            || line.starts_with("fn store_rate(")
            || line.starts_with("fn ell(")
            || line.starts_with("fn arx_box(")
            || line.starts_with("const fn digest_bytes(")
            || line.starts_with("const fn state_words(")
            || line.starts_with("const fn steps_")
            || line.starts_with("fn hash256(")
            || line.starts_with("fn hash512(")
            || line.starts_with("fn absorb<")
            || line.starts_with("fn checked_output<")
            || line.starts_with("fn s_box(")
            || line.starts_with("fn sub_bytes(")
            || line.starts_with("fn shift_rows(")
            || line.starts_with("fn mix_columns(")
            || line.starts_with("fn aes_enc(")
            || line.starts_with("fn mix256(")
            || line.starts_with("fn mix512(")
            || line.starts_with("unsafe fn ")
            || line.starts_with("fn push(")
            || line.starts_with("fn format_name(")
            || line.starts_with("fn generate_iv(")
            || line.starts_with("fn fmt(")
            || line.starts_with("fn drop(")
            || line.starts_with("fn zeroize(")
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
pub const fn new() {}
/// VARIABLE TIME.
#[inline]
pub fn accepted() {}
/// Constant time and variable time.
fn compress() {}
fn process_block() {}
/// Constant time.
pub(crate) fn helper() {}
fn push() {}
pub struct Parameters {}
fn try_update() {}
/// Constant time with respect to the message.
fn fmt() {}
fn fmt(&self) {}
/// Constant time.
fn drop(&mut self) {}
fn zeroize(&mut self) {}
";
    let (checked, missing) = missing_timing_docs(fixture);
    assert_eq!(checked, 11);
    assert_eq!(
        missing,
        [
            "pub const fn new() {}",
            "fn compress() {}",
            "fn process_block() {}",
            "fn push() {}",
            "fn fmt(&self) {}",
            "fn zeroize(&mut self) {}",
        ]
    );
}

#[test]
fn every_digest_and_crate_visible_helper_has_an_unambiguous_timing_doc() {
    for (name, source) in [
        ("haraka.rs", include_str!("../src/haraka.rs")),
        (
            "haraka/portable.rs",
            include_str!("../src/haraka/portable.rs"),
        ),
        ("haraka/aesni.rs", include_str!("../src/haraka/aesni.rs")),
        ("md_buffer.rs", include_str!("../src/md_buffer.rs")),
        ("photon_beetle.rs", include_str!("../src/photon_beetle.rs")),
        ("sparkle.rs", include_str!("../src/sparkle.rs")),
        ("tiger.rs", include_str!("../src/tiger.rs")),
        ("whirlpool.rs", include_str!("../src/whirlpool.rs")),
        ("xoodyak.rs", include_str!("../src/xoodyak.rs")),
    ] {
        let (checked, missing) = missing_timing_docs(source);
        assert!(checked > 0, "no declarations scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
