#![cfg(feature = "whirlpool")]
//! Whirlpool tests: the ISO/IEC 10118-3 vectors of Bouncy Castle's
//! `WhirlpoolDigestTest`, with its 31 zero bytes and a million `'a'` bytes,
//! and messages on the padding boundaries with expected digests computed by
//! OpenSSL; then the API contract every digest shares.

mod common;

use common::{check_contract, counting_message, hex_digest};
use tc_digest::{Digest, TryDigest};
use tc_misc_digest::WhirlpoolDigest;

#[test]
fn whirlpool_matches_the_iso_vectors_of_bouncy_castle() {
    for (message, expected) in [
        (
            &b""[..],
            "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7\
             3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3",
        ),
        (
            b"a",
            "8aca2602792aec6f11a67206531fb7d7f0dff59413145e6973c45001d0087b42\
             d11bc645413aeff63a42391a39145a591a92200d560195e53b478584fdae231a",
        ),
        (
            b"abc",
            "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c\
             7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5",
        ),
        (
            b"message digest",
            "378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b\
             8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e",
        ),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "f1d754662636ffe92c82ebb9212a484a8d38631ead4238f5442ee13b8054e41b\
             08bf2a9251c30b6a0b8aae86177ab4a6f68f673e7207865d5d9819a3dba4eb3b",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "dc37e008cf9ee69bf11f00ed9aba26901dd7c28cdec066cc6af42e40f82f3a1e\
             08eba26629129d8fb7cb57211b9281a65517cc879d7b962142c65f5a7af01467",
        ),
        (
            b"1234567890123456789012345678901234567890\
              1234567890123456789012345678901234567890",
            "466ef18babb0154d25b9d38a6414f5c08784372bccb204d6549c4afadb601429\
             4d5bd8df2a6c44e538cd047b2681a51a2c60481e88c5a20b2c2a80cf3a9a083b",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijk",
            "2a987ea40f917061f5d6f0a0e4644f488a7a5a52deee656207c562f988e95c69\
             16bdc8031bc5be1b7b947639fe050b56939baaa0adff9ae6745b7b181c3be3fd",
        ),
    ] {
        assert_eq!(hex_digest(&mut WhirlpoolDigest::new(), message), expected);
    }
}

#[test]
fn whirlpool_matches_bouncy_castle_on_31_zero_bytes() {
    assert_eq!(
        hex_digest(&mut WhirlpoolDigest::new(), &[0; 31]),
        "3e3f188f8febbeb17a933feaf7fe53a4858d80c915ad6a1418f0318e68d49b4e\
         459223cd414e0fbc8a57578fd755d86e827abef4070fc1503e25d99e382f72ba"
    );
}

#[test]
fn whirlpool_matches_bouncy_castle_on_a_million_a_bytes() {
    let mut digest = WhirlpoolDigest::new();
    for _ in 0..1000 {
        digest.update(&[b'a'; 1000]);
    }
    assert_eq!(
        hex_digest(&mut digest, b""),
        "0c99005beb57eff50a7cf005560ddf5d29057fd86b20bfd62deca0f1ccea4af5\
         1fc15490eddc47af32bb2b66c34ff9ad8c6008ad677f77126953b226e4ed8b01"
    );
}

/// Hashes the messages `0, 1, 2, ...` on the padding boundaries of 64-byte
/// blocks with a 32-byte length field: the length field just fits (31, 95),
/// just spills into another block (32, 96), or the message fills whole blocks
/// (64, 128). The boundaries of an 8-byte length field (55, 56, 111, 112) are
/// checked as well.
#[test]
fn whirlpool_matches_openssl_on_padding_boundaries() {
    for (len, expected) in [
        (
            31,
            "58bee92be003ccc34f9ce8c0b323c6baf1297460baab4998cb3b52d2bbaa24d1\
             b06cb597eb2e609a008572ff93710e3a7f42ac53e3ff09d4733757eaca41e20c",
        ),
        (
            32,
            "888aeb1be2becb28598556a128afea037d0689c8d13d9894f1416b2c48b2551c\
             b2fda321a26cc4d7e1c87332d7a3c18ffb455c92c0e7aaf829fa40b8a28bb656",
        ),
        (
            55,
            "a385fe66f8c852638f5be44503b680298ebbf27dbd9f20b1a0447215c0e2c107\
             8926002113a71c78148d5019fb22c8132dd05356c78a1a8d8e4eec5a6442dba9",
        ),
        (
            56,
            "218336585a419e9877cb63387c5e759fc93f0fe1a7ba717b8be9b2302393e0d1\
             4def2f749d138692d0a0296f1c792b567f40037dd2b8787f1f47ff363cf34f37",
        ),
        (
            64,
            "5c3c6f524c8ae1e7a4f76b84977b1560e78eb568e2fd8d72699ad79186481bd4\
             2b53ab39a0b741d9c098a4ecb01f3eccf3844cf1b73a9355ee5d496a2a1fb5b3",
        ),
        (
            95,
            "c70f19baea7420a7482c9c54cbb689a9ab93e4f8538edc2371a1edb3a103dfb7\
             176e04df170ff71ef46dfdac1e8f9cd6ff96115be1efc271a56bdcfb67d29e67",
        ),
        (
            96,
            "8bbccfc8815786add9f108f4381a2b084179002ae940add4c42aa2550c353cd0\
             351c2f7f1bd544d8f268fa332b0e803838318a39079e9d93269a01eaf9cac967",
        ),
        (
            111,
            "86618429b8720adcbc8b9feaed8bd44e0848572cb6137213273563ebfda85924\
             0e17dfdaff68b09953f1853c9e7ef217875e7bd6959e76dc3a1ce5f548b76ceb",
        ),
        (
            112,
            "96439a93295b5c479f0310b28377fc10df81b593ac233556b15897f1fa3886c9\
             40639aff2eceb29894da884626b4811254fe2622ec7b4577087d9046c96aa556",
        ),
        (
            128,
            "803a3b37c89e84fbbec75bee3d00dd728ffc4246b5a5e989dc8dc2cd0f793796\
             6ab78c79e1d4648ee6eb40f3d70491cb46b8ab42e155672e2ab8374fcf70dd79",
        ),
    ] {
        assert_eq!(
            hex_digest(&mut WhirlpoolDigest::new(), &counting_message(len)),
            expected,
            "Whirlpool of a {len}-byte message"
        );
    }
}

#[test]
fn whirlpool_keeps_the_digest_contract() {
    check_contract(WhirlpoolDigest::new);
}

#[test]
fn accessors_report_the_algorithm() {
    let digest = WhirlpoolDigest::new();
    assert_eq!(digest.to_string(), "Whirlpool");
    assert_eq!(digest.digest_size(), 64);
    assert_eq!(digest.byte_length(), 64);
}

#[test]
fn const_constructor_matches_default() {
    const WHIRLPOOL: WhirlpoolDigest = WhirlpoolDigest::new();
    let mut from_const = WHIRLPOOL;
    assert_eq!(
        hex_digest(&mut from_const, b"abc"),
        hex_digest(&mut WhirlpoolDigest::default(), b"abc")
    );
}

#[test]
fn the_digest_runs_a_destructor() {
    // The wipe itself cannot be observed without unsafe code; this guards
    // against the destructor that performs it disappearing.
    assert!(std::mem::needs_drop::<WhirlpoolDigest>());
}
