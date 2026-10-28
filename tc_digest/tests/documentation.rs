//! Every adapter type and helper documents its timing.

fn missing_timing_docs(source: &str) -> (usize, Vec<String>) {
    let mut docs = String::new();
    let mut attribute_depth = 0_i32;
    let mut checked = 0;
    let mut missing = Vec::new();
    for line in source.lines().map(str::trim) {
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
        if line.starts_with("pub struct ")
            || line.starts_with("pub fn ")
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
fn every_adapter_and_helper_has_an_unambiguous_timing_doc() {
    for (name, source, minimum) in [
        ("null.rs", include_str!("../src/util/null.rs"), 4),
        ("prehash.rs", include_str!("../src/util/prehash.rs"), 9),
        ("shortened.rs", include_str!("../src/util/shortened.rs"), 4),
    ] {
        let (checked, missing) = missing_timing_docs(source);
        assert!(
            checked >= minimum,
            "only {checked} declarations scanned in {name}"
        );
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
