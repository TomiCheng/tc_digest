//! Known-answer tests: RFC 1319's multi-block vectors for MD2, and for MD4
//! and MD5 messages on the padding boundaries and a million `'a'` bytes, with
//! expected digests computed by OpenSSL.

mod common;

use common::{NamedDigest, counting_message, hex_digest};
use tc_md::{Md2Digest, Md4Digest, Md5Digest};

/// Message lengths on the padding boundaries of 64- and 128-byte blocks: the
/// length field just fits (55, 111), just spills into another block (56,
/// 112), or the message fills whole blocks (64, 128).
const BOUNDARY_LENGTHS: [usize; 6] = [55, 56, 64, 111, 112, 128];

/// Hashes the messages `0, 1, 2, ...` of each boundary length and compares
/// them with digests computed by OpenSSL.
fn check_boundaries(digest: &mut dyn NamedDigest, expected: [&str; 6]) {
    for (len, expected) in BOUNDARY_LENGTHS.into_iter().zip(expected) {
        assert_eq!(
            hex_digest(digest, &counting_message(len)),
            expected,
            "{digest} of a {len}-byte message"
        );
    }
}

/// MD4 on every boundary length.
#[test]
fn md4_matches_openssl_on_padding_boundaries() {
    check_boundaries(
        &mut Md4Digest::new(),
        [
            "cc8a7f2bd608e3eeecb7f121d13bea55",
            "b8e94b6408bbfa6ec9805bf21bc05cbd",
            "2de6578f0e7898fa17acd84b79685d3a",
            "659905751d1f614a78ecbb56d4398d06",
            "594691b38126e028352da5b28adfd416",
            "e1275970eb67d2d996e6e658270aa149",
        ],
    );
}

/// MD5 on every boundary length.
#[test]
fn md5_matches_openssl_on_padding_boundaries() {
    check_boundaries(
        &mut Md5Digest::new(),
        [
            "6912ee65fff2d9f9ce2508cddf8bcda0",
            "51fdd1acda72405dfdfa03fcb85896d7",
            "b2d3f56bc197fd985d5965079b5e7148",
            "4fad3ab7d8546851ec1bb63ea7e6f5a8",
            "d1fec2ac3715e791ca5f489f300381b3",
            "37eff01866ba3f538421b30b7cbefcac",
        ],
    );
}

/// One million repetitions of `'a'`.
#[test]
fn md4_and_md5_match_the_million_a_vector() {
    let message = [b'a'; 1_000_000];
    assert_eq!(
        hex_digest(&mut Md4Digest::new(), &message),
        "bbce80cc6bb65e5c6745e30d4eeca9a4"
    );
    assert_eq!(
        hex_digest(&mut Md5Digest::new(), &message),
        "7707d6ae4e027c70eea2a935c2296f21"
    );
}

/// The two RFC 1319 vectors that span several 16-byte MD2 blocks.
#[test]
fn md2_matches_the_multi_block_rfc_1319_vectors() {
    assert_eq!(
        hex_digest(
            &mut Md2Digest::new(),
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        ),
        "da33def2a42df13975352846c30338cd"
    );
    assert_eq!(
        hex_digest(
            &mut Md2Digest::new(),
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
        ),
        "d5976f79d83d3a0dc9806c3c66f3efd8"
    );
}
