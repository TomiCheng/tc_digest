//! Known-answer tests: FIPS 180-4's long-message vectors and messages on
//! the padding boundaries, with expected digests computed by OpenSSL.

mod common;

use common::{NamedDigest, counting_message, hex_digest};
use tc_digest::Digest;
use tc_sha::{Sha1Digest, Sha224Digest, Sha256Digest, Sha384Digest, Sha512Digest, Sha512tDigest};

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

/// SHA-1 on every boundary length.
#[test]
fn sha1_matches_openssl_on_padding_boundaries() {
    check_boundaries(
        &mut Sha1Digest::new(),
        [
            "8ae2d46729cfe68ff927af5eec9c7d1b66d65ac2",
            "636e2ec698dac903498e648bd2f3af641d3c88cb",
            "c6138d514ffa2135bfce0ed0b8fac65669917ec7",
            "bc544e24573d592290fdaff8ecf3f7f2b00cd483",
            "e4ce142d09a84a8645338dd6535cbfaaf800d320",
            "e6434bc401f98603d7eda504790c98c67385d535",
        ],
    );
}

/// SHA-224 on every boundary length.
#[test]
fn sha224_matches_openssl_on_padding_boundaries() {
    check_boundaries(
        &mut Sha224Digest::new(),
        [
            "8991dfba74284e04dc7581c7c3e4068ff6cb7a63733361429834bb56",
            "2b2cd637c16ad7290bb067ad7d8fd04e204fa43a84366afc7130f4ef",
            "c37b88a3522dbf7ac30d1c68ea397ac11d4773571aed01ddab73531e",
            "1aeef583c448a9ae00fbc931b50bc0da5bb8323e616b11076cee8b44",
            "01e5abf50619b5c2078e754eddedcf4de8d31185a2219313cb91a8c9",
            "67d88da33fd632d8742424791dface672ff59d597fe38b3f2a998386",
        ],
    );
}

/// SHA-256 on every boundary length.
#[test]
fn sha256_matches_openssl_on_padding_boundaries() {
    check_boundaries(
        &mut Sha256Digest::new(),
        [
            "463eb28e72f82e0a96c0a4cc53690c571281131f672aa229e0d45ae59b598b59",
            "da2ae4d6b36748f2a318f23e7ab1dfdf45acdc9d049bd80e59de82a60895f562",
            "fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108",
            "60780e9451bdc43cf4530ffc95cbb0c4eb24dae2c39f55f334d679e076c08065",
            "09373f127d34e61dbbaa8bc4499c87074f2ddb10e1b465f506d7d70a15011979",
            "471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5",
        ],
    );
}

/// SHA-384 on every boundary length.
#[test]
fn sha384_matches_openssl_on_padding_boundaries() {
    check_boundaries(
        &mut Sha384Digest::new(),
        [
            "dcedb6b590edb4efa849c801e6b6490657a5c1e64f69269f5f63c9267f6223de\
             24cea7aaa6b267d9bcecc15147b6c875",
            "7b9132d597b8873ad55bbc30f18ed3f2c9f340e7de69fb5774056c71a06d9bc2\
             b14137e9e1c68b6b645fed28b188249d",
            "9f2c9eb7116b3d7a4ba84a74a4d4eff8a5efcf54b6d7b662693c38577914c73a\
             214766f0a175339bb0895a863824fc0a",
            "f5f9fe110d809d34029de262a01b208356caec6e054c7f926b2591f6c9780579\
             d4b59f5578c6f531a84f158a33660cef",
            "33ba080ec0ccb378e4e95fed3b26c23aa1a280476e007519ee47f60cd9c5c8a6\
             5d627259a9aa2fd33ca06d3c14ee5548",
            "ca2385773319124534111a36d0581fc3f00815e907034b90cff9c3a861e126a7\
             41d5dfcff65a417b6d7296863ac0ec17",
        ],
    );
}

/// SHA-512 on every boundary length.
#[test]
fn sha512_matches_openssl_on_padding_boundaries() {
    check_boundaries(
        &mut Sha512Digest::new(),
        [
            "6856647f269c2ee3d8128f0b25427659d880641ef343300dd3cd4679168f58d6\
             527fda70b4ebc854e2065e172b7d58c1536992c0810599259ba84a2b40c65414",
            "8b12b2f6fe400a51d29656e2b8c42a1bbfe6fcf3e425da430db05d1a2dda1479\
             0dee20fa8b22d8762afffe4988a5c98a4430d22a17e41e23d90fa61ab75671a9",
            "ee4320ebaf3fdb4f2c832b137200c08e235e0fa7bbd0eb1740c7063ba8a0d151\
             da77e003398e1714a955d475b05e3e950b639503b452ec185de4229bc4873949",
            "a1a111449b198d9b1f538bad7f3fc1022b3a5b1a5e90a0bc860de8512746cbc3\
             1599e6c834de3a3235327af0b51ff57bf7acf1974a73014d9c3953812edc7c8d",
            "c5fbd731d19d2ae1180f001be72c2c1aaba1d7b094b3748880e24593b8e117a7\
             50e11c1bd867cc2f96dace8c8b74abd2d5c4f236be444e77d30d1916174070b9",
            "1dffd5e3adb71d45d2245939665521ae001a317a03720a45732ba1900ca3b835\
             1fc5c9b4ca513eba6f80bc7b1d1fdad4abd13491cb824d61b08d8c0e1561b3f7",
        ],
    );
}

/// SHA-512/224 on every boundary length.
#[test]
fn sha512_224_matches_openssl_on_padding_boundaries() {
    check_boundaries(
        &mut Sha512tDigest::new(224),
        [
            "4bc333b55c3237ed85ac21b6b3dfb70987c33ce04e20c2de6142d681",
            "df1bb702813c49110142bc858073e618ab22af52faf8d5f0403d3ff0",
            "9e2437140847453434acb859bc4f842e9fb4a4b55bd9dc164b74cea4",
            "f8810ee322210d0f4cbd7a4e92e7d7e72b63d2777dcb531e13ddd690",
            "8099918892ebbd31215c9bb5e4e53c0b52927b000ced0720d2c65a22",
            "49a64b72a88a3c93432b6e4c59a1b4908403f70e46e13bf7494fbe88",
        ],
    );
}

/// SHA-512/256 on every boundary length.
#[test]
fn sha512_256_matches_openssl_on_padding_boundaries() {
    check_boundaries(
        &mut Sha512tDigest::new(256),
        [
            "7dd58a7c3285d6436f4b8876a4e3ce63bae92a11a5453c46a6032c5e469bf40c",
            "c06d2d4f6d22414491b36e215de341782922ec36900cfca39f4a707a5379f51a",
            "c9e483b9622515e83259e1e075746b70142cb1217863fb8c85fae33256f4188a",
            "bd209f60b0d04102a09175297fd255367e54b5a5605b928635c606306914363f",
            "2cafeb0882cc405167e9a255b8581a66dc683212474902dd453dbca20a94e61a",
            "2ff11194b2aec1f943cb5f130ba647c151334068083194d7281a55d607ae255f",
        ],
    );
}

/// FIPS 180-4's 896-bit message, for the SHA-512/t lengths the inline tests
/// cover only with `""` and `"abc"`.
#[test]
fn sha512_t_matches_the_896_bit_example() {
    let message = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
                    ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    assert_eq!(
        hex_digest(&mut Sha512tDigest::new(224), message),
        "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9"
    );
    assert_eq!(
        hex_digest(&mut Sha512tDigest::new(256), message),
        "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a"
    );
}

/// One million repetitions of `'a'`, fed in uneven pieces.
#[test]
fn every_digest_matches_the_million_a_vector() {
    let cases: [(&mut dyn NamedDigest, &str); 7] = [
        (
            &mut Sha1Digest::new(),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
        ),
        (
            &mut Sha224Digest::new(),
            "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67",
        ),
        (
            &mut Sha256Digest::new(),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        ),
        (
            &mut Sha384Digest::new(),
            "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b\
             07b8b3dc38ecc4ebae97ddd87f3d8985",
        ),
        (
            &mut Sha512Digest::new(),
            "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
             de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
        ),
        (
            &mut Sha512tDigest::new(224),
            "37ab331d76f0d36de422bd0edeb22a28accd487b7a8453ae965dd287",
        ),
        (
            &mut Sha512tDigest::new(256),
            "9a59a052930187a97038cae692f30708aa6491923ef5194394dc68d56c74fb21",
        ),
    ];
    for (digest, expected) in cases {
        assert_eq!(million_a_hex(digest), expected, "{digest}");
    }
}

fn million_a_hex<D: Digest + ?Sized>(digest: &mut D) -> String {
    let chunk = [b'a'; 1000];
    // 999 * 1001 + 1 = 1_000_000, in pieces that never align with a block.
    for _ in 0..999 {
        digest.update(&chunk);
        digest.update_byte(b'a');
    }
    digest.update(b"a");
    hex_digest(digest, b"")
}
