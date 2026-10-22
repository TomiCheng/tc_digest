//! Known-answer tests: SHA-3 on the rate boundaries and FIPS 202's 1600-bit
//! message, and SHAKE read one byte past a squeeze block, with the expected
//! outputs computed by Python's hashlib, which uses OpenSSL.

use tc_digest::{Digest, TryDigest, Xof};
use tc_keccak::{Sha3Digest, ShakeDigest};

/// The message `0, 1, 2, ...` of `len` bytes, wrapping at 256.
fn counting_message(len: usize) -> Vec<u8> {
    (0..len).map(|i| i as u8).collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `(bits, message length, digest)` for messages one byte short of a block, a
/// whole block, one byte over and two blocks.
const SHA3_RATE_BOUNDARIES: &[(usize, usize, &str)] = &[
    (
        224,
        143,
        "64d0e8a1be3cf30ef6727b30a6e428f7f068d44634c943d277ad8e7f",
    ),
    (
        224,
        144,
        "5be75e6a08f19913a1d8036c056cc4556b98dc90aeca3f2a0664dedc",
    ),
    (
        224,
        145,
        "90b861ac1b1598459ad8337afa9933ce2f1a6f972c57daf8fc2737e4",
    ),
    (
        224,
        288,
        "e0ae33f2dd63c31ef87f219c9b80c897669974b73d8a9fe64500887b",
    ),
    (
        256,
        135,
        "fded8fd9d6551c601eeb3b7c6bc5e5cfd8aad1d015b7e9aaa9c9b9475231d5e2",
    ),
    (
        256,
        136,
        "cf3ccff92480a29160c2d38317c430e14749bfee1788106957dfe73f8c4930e5",
    ),
    (
        256,
        137,
        "ce9d7dc90913ee5d92745019479a5352c6d6279bef18ed07dc0a83ee8084daca",
    ),
    (
        256,
        272,
        "0b21ec4a8eff6d179e09ba9fe0ab08515b24e0923fbf419f5c30a38e64577db5",
    ),
    (
        384,
        103,
        "1f91ee551ad18f268876d1fc262f137fe196580216c5193819a95ec5222537d2\
         a658dd129c3d8080e65ec7460f1f4704",
    ),
    (
        384,
        104,
        "5b8d0d5cf8b41be507be8fcbfcbdbac3a28eb368d430fed6780aaa78a93a8da4\
         a6c50485949ca344f228be91a96005a3",
    ),
    (
        384,
        105,
        "4a2f0a8f2f1f4cc4605cc2537e0be28cf8b465c30f0a54b494a7128ec54ee4e8\
         5706b5e47a5697344d15cbf85680cd40",
    ),
    (
        384,
        208,
        "13a929eb9e4ac18a07de84b17e79bb420a86924b9dc4cd80038dd61f17770fc4\
         2460f2a0a717dd26fb6b6b4de357ae02",
    ),
    (
        512,
        71,
        "3ccc850d53a1287af7b4560b2ef0d43eb5d9a80d62a0e9cf1dbc040135921104\
         d4395168e90bfc871773ebb34bca1bd67056e1cc7dc7a48ff7c3167d389f117c",
    ),
    (
        512,
        72,
        "5d63f2bbe971a983ac6847480106e4e1264ee3a0befd79954914e1d86e795b2e\
         18238f12fc5e46cb9cc78efdec610a93647cc04e1c23d8caaa6a58c21dd26c07",
    ),
    (
        512,
        73,
        "921d9b7b2b0f3066a1646dbb058c979cb3925dec0f8c269faaa7f9648e73465a\
         e55ec527257d5d5e1cfdbf5d6799bea1004b6186f5108c74e3b92fe924166558",
    ),
    (
        512,
        144,
        "e1951b8bcb58ca75a34af80a7a2b765cad4257fe383a79b55bf21f180b75f6e5\
         b08f09598851eeea7d13486387618d6c6bf88cf23c0088a3f783f59a06d60493",
    ),
];

#[test]
fn sha3_matches_openssl_on_the_rate_boundaries() {
    for &(bits, len, expected) in SHA3_RATE_BOUNDARIES {
        let mut sha3 = Sha3Digest::new(bits);
        sha3.update(&counting_message(len));
        let mut output = vec![0; sha3.digest_size()];
        sha3.do_final(&mut output);
        assert_eq!(hex(&output), expected, "SHA3-{bits} of {len} bytes");
    }
}

/// `(bits, digest)` of FIPS 202's 1600-bit message, 200 bytes of `0xa3`.
const SHA3_LONG_MESSAGE: &[(usize, &str)] = &[
    (
        224,
        "9376816aba503f72f96ce7eb65ac095deee3be4bf9bbc2a1cb7e11e0",
    ),
    (
        256,
        "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787",
    ),
    (
        384,
        "1881de2ca7e41ef95dc4732b8f5f002b189cc1e42b74168ed1732649ce1dbcdd\
         76197a31fd55ee989f2d7050dd473e8f",
    ),
    (
        512,
        "e76dfad22084a8b1467fcf2ffa58361bec7628edf5f3fdc0e4805dc48caeeca8\
         1b7c13c30adf52a3659584739a2df46be589c51ca1a4a8416df6545a1ce8ba00",
    ),
];

#[test]
fn sha3_matches_openssl_on_the_fips_202_long_message() {
    for &(bits, expected) in SHA3_LONG_MESSAGE {
        let mut sha3 = Sha3Digest::new(bits);
        sha3.update(&[0xa3; 200]);
        let mut output = vec![0; sha3.digest_size()];
        sha3.do_final(&mut output);
        assert_eq!(hex(&output), expected, "SHA3-{bits}");
    }
}

/// `(bits, message length, output length, output)`, each output one byte
/// longer than a block, so squeezing crosses into a second permutation.
const SHAKE_ACROSS_BLOCKS: &[(usize, usize, usize, &str)] = &[
    (
        128,
        167,
        169,
        "1e552791cc4e93a0d4a8dc47ae49228c2faa869e40e628f6ace477aec3f1ca7a\
         efe1c1245cf82c265168ad2985121aedd72335ae1187a36742c746cf2b40cb30\
         b7c994c5ea9e44c40f2014686bc7ab0237ad3973e48dd88d48c8bc8b28be98c7\
         729a946670a0788211c3b239fdcb95d51b6120463c631286817cda1dbc9f3e3c\
         376e40fc2d6ba3d4df72d12177de6efccb84dd15f9f2687065b8ad00217c27e7\
         5b7d11c5214b731ed3",
    ),
    (
        128,
        168,
        169,
        "f15277eb61c4908d44a2853f3cde071ae2ed7a23461fbe162a1a98cf6875059c\
         06ffeebfca31afd9976e5592a3e7e5e94a665a8befa4b64a7f089cc0f3572403\
         20ad264522532b1759b38ec23b950e7af66e0a7515a7d233174ebb03300ad106\
         b25f5405327efb384502fcb438f45553e1fed3387262b2641868dc9871903536\
         fcd83d0776558a6efb637c906b17a4bddd9168c14854fd2afc0cbc09019d044e\
         3a90e321231c3a61f4",
    ),
    (
        256,
        135,
        137,
        "c45dae624ad8a2f5aa7bac9d7557737fd91c96eedb70a6be5574d57a844eade0\
         7f4056bf081a1098101cea8132188c422136feb4687d1e2209f3fd28bedfb8f4\
         468cba8501763511f507c9c14537403bf7804a89607b4c3f5afd484ec0c411c6\
         1e61d8784b2a0cb281ef9f44a4e32732adaba131875b0e34d587d1e63fea83b1\
         77a04230d041b8f96e",
    ),
    (
        256,
        136,
        137,
        "b7ff4073b3f5a8eabd6e17705ca7f6761a31058f9df781a6a47e3a3063b9d67a\
         757e8dbf043dac48d2154e46d59c0b9e8bc36ba035153691fbe83b9eff5dae4a\
         0aa01d73c984c49adc271297af1baa96931f24ef47a11781fed7722a293e2236\
         47e4be704fd5d63ee4e15a4a7cf7ad586b561b840e6225e6aae344dbe9a15fb1\
         55e4fa2ab7d7df09be",
    ),
];

#[test]
fn shake_matches_openssl_across_a_squeeze_block() {
    for &(bits, len, out_len, expected) in SHAKE_ACROSS_BLOCKS {
        let mut shake = ShakeDigest::new(bits);
        shake.update(&counting_message(len));
        let mut output = vec![0; out_len];
        shake.output_final(&mut output);
        assert_eq!(hex(&output), expected, "SHAKE{bits} of {len} bytes");
    }
}
