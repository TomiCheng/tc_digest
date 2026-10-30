//! Known-answer tests: the examples of DSTU 7564:2014 and the further
//! vectors of Bouncy Castle's `Dstu7564Test`, including the padding boundaries
//! of the 64-byte block; and digests computed by Bouncy Castle on the padding
//! boundaries of the 128-byte block and for one million `'a'` bytes.

mod common;

use common::{counting_message, hex_digest};
use tc_digest::Digest;
use tc_dstu7564::Dstu7564Digest;

/// Hashes the counting message `0, 1, 2, ...` of `len` bytes.
fn counting_digest(bit_length: usize, len: usize) -> String {
    hex_digest(&mut Dstu7564Digest::new(bit_length), &counting_message(len))
}

/// The examples of the standard, which hash counting messages, and the
/// one-byte message `ff`.
#[test]
fn dstu7564_matches_the_examples_of_the_standard() {
    for (bit_length, len, expected) in [
        (
            256,
            64,
            "08f4ee6f1be6903b324c4e27990cb24ef69dd58dbe84813ee0a52f6631239875",
        ),
        (
            256,
            128,
            "0a9474e645a7d25e255e9e89fff42ec7eb31349007059284f0b182e452bda882",
        ),
        (
            256,
            256,
            "d305a32b963d149dc765f68594505d4077024f836c1bf03806e1624ce176c08f",
        ),
        (
            384,
            95,
            "d9021692d84e5175735654846ba751e6d0ed0fac36dfbc0841287dcb0b5584c7\
             5016c3decc2a6e47c50b2f3811e351b8",
        ),
        (
            512,
            64,
            "3813e2109118cdfb5a6d5e72f7208dccc80a2dfb3afdfb02f46992b5edbe536b\
             3560dd1d7e29c6f53978af58b444e37ba685c0dd910533ba5d78efffc13de62a",
        ),
        (
            512,
            128,
            "76ed1ac28b1d0143013ffa87213b4090b356441263c13e03fa060a8cada32b97\
             9635657f256b15d5fca4a174de029f0b1b4387c878fcc1c00e8705d783fd7ffe",
        ),
        (
            512,
            256,
            "0dd03d7350c409cb3c29c25893a0724f6b133fa8b9eb90a64d1a8fa93b565566\
             11eb187d715a956b107e3bfc76482298133a9ce8cbc0bd5e1436a5b197284f7e",
        ),
        (
            512,
            192,
            "b189bfe987f682f5f167f0d7fa565330e126b6e592b1c55d44299064ef95b1a5\
             7f3c2d0ecf17869d1d199ebbd02e8857fb8add67a8c31f56cd82c016cf743121",
        ),
        (
            512,
            0,
            "656b2f4cd71462388b64a37043ea55dbe445d452aecd46c3298343314ef04019\
             bcfa3f04265a9857f91be91fce197096187ceda78c9c1c021c294a0689198538",
        ),
    ] {
        assert_eq!(
            counting_digest(bit_length, len),
            expected,
            "DSTU 7564-{bit_length} of {len} counting bytes"
        );
    }
    assert_eq!(
        hex_digest(&mut Dstu7564Digest::new(512), &[0xff]),
        "871b18cf754b72740307a97b449abeb32b64444cc0d5a4d65830ae5456837a72\
         d8458f12c8f06c98c616abe11897f86263b5cb77c420fb375374bec52b6d0292"
    );
}

#[test]
fn dstu7564_256_matches_bouncy_castle_on_text_messages() {
    for (message, expected) in [
        (
            &b""[..],
            "cd5101d1ccdf0d1d1f4ada56e888cd724ca1a0838a3521e7131d4fb78d0f5eb6",
        ),
        (
            b"a",
            "c51a1d639596fb613d86557314a150c40f8fff3de48bc93a3b03c161f4105ee4",
        ),
        (
            b"abc",
            "0bd1b36109f1318411a0517315aa46b8839df06622a278676f5487996c9cfc04",
        ),
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
              ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "02621dbb53f2c7001be64d7308ecb80d21ba7797c92e98d1efc240d41e4c414b",
        ),
    ] {
        assert_eq!(hex_digest(&mut Dstu7564Digest::new(256), message), expected);
    }
}

/// Bouncy Castle's overflow tests: around 64 - 13 = 51 bytes the 0x80 marker
/// and the 12-byte length field stop fitting into the final 64-byte block.
#[test]
fn dstu7564_256_matches_bouncy_castle_on_padding_boundaries() {
    for (len, expected) in [
        (
            51,
            "6f8f0a3f8261af77581ab01cb89d4cb5ed87ca1d9954f11d5586e94b45c82fb8",
        ),
        (
            52,
            "8b6fe2ba77e684b2a1ac82232f4efc49f681cd18c82a0cfff530186a2fc642d2",
        ),
        (
            53,
            "837f2b0cbe39a4defdfcb44272288d4091cab850161c70695d7831fc5f00e171",
        ),
        (
            54,
            "21d423d5b8c7f18a0da42cdd95b36b66344125e2adc6edeab5899926442113bc",
        ),
        (
            55,
            "0e7bf74464b81b3ae7d904170776d29f4b02a7227da578dd562d01027af7fd0e",
        ),
        (
            56,
            "badea1f49cbcec94acec52b4c695acdddd786cca5a6763929f341a58c5134b3b",
        ),
        (
            57,
            "a13b5f6f53ee043292ed65b66c1d49759be4d2fe0c2f6148f2416487965f7bde",
        ),
        (
            63,
            "03a44a02c9ffafb43addb290bbcf3b8168f624e8cbd332dc6a9dc7df9d39cbc2",
        ),
        (
            64,
            "08f4ee6f1be6903b324c4e27990cb24ef69dd58dbe84813ee0a52f6631239875",
        ),
        (
            65,
            "a81c2fb92351f370050b7c36cd51736d5603a50ec1106cbd5fe1c9be2e5c77a6",
        ),
        (
            1023,
            "6bfc5ec8c1f5963fbed89da115d86e9330634eca341dd42fd94a7007e4af7942",
        ),
    ] {
        assert_eq!(counting_digest(256, len), expected, "{len} bytes");
    }
}

/// Around 128 - 13 = 115 bytes the marker and the length field stop fitting
/// into the final 128-byte block of the longer digests.
#[test]
fn dstu7564_384_and_512_match_bouncy_castle_on_padding_boundaries() {
    for (bit_length, len, expected) in [
        (
            384,
            115,
            "819f24ad56ce42c76a59adc36672e71b15fbd5d3e1ddfae96fd88bd860fe4a1c\
             dae8d2465b5e9238fd3eb695a69b4b2f",
        ),
        (
            512,
            115,
            "0ce7a17a34c4785da207da4ac39a54f2819f24ad56ce42c76a59adc36672e71b\
             15fbd5d3e1ddfae96fd88bd860fe4a1cdae8d2465b5e9238fd3eb695a69b4b2f",
        ),
        (
            384,
            116,
            "c55b19c315797f822744025d4de8bab88d3cdb9db9c965d5db4866dcedd485b4\
             07a95f2c2e6340774d8993b9d9fe505e",
        ),
        (
            512,
            116,
            "306bb714aed5988733a6011062004452c55b19c315797f822744025d4de8bab8\
             8d3cdb9db9c965d5db4866dcedd485b407a95f2c2e6340774d8993b9d9fe505e",
        ),
        (
            384,
            127,
            "8cf0de519df78ece9476193347ab5acd3ff0c3633ab78d9cd8dc6ef02d2343f1\
             28612a00952c9b17ad719a382ecc19ff",
        ),
        (
            512,
            127,
            "45d00504bc31f2545b2a5c9742ce26118cf0de519df78ece9476193347ab5acd\
             3ff0c3633ab78d9cd8dc6ef02d2343f128612a00952c9b17ad719a382ecc19ff",
        ),
        (
            384,
            128,
            "b356441263c13e03fa060a8cada32b979635657f256b15d5fca4a174de029f0b\
             1b4387c878fcc1c00e8705d783fd7ffe",
        ),
        (
            512,
            128,
            "76ed1ac28b1d0143013ffa87213b4090b356441263c13e03fa060a8cada32b97\
             9635657f256b15d5fca4a174de029f0b1b4387c878fcc1c00e8705d783fd7ffe",
        ),
        (
            384,
            129,
            "29369df490d2d2934d84c6f8f15dec73176b7bc4dfff211e435dd4784bdea21a\
             d6aefd43d49a9f57994641e8b2fce144",
        ),
        (
            512,
            129,
            "0137f2f8f9f16b55586dca3e24229f2429369df490d2d2934d84c6f8f15dec73\
             176b7bc4dfff211e435dd4784bdea21ad6aefd43d49a9f57994641e8b2fce144",
        ),
        (
            384,
            243,
            "89a81565f3ed83db27ca839022310803583fe52211d898fefe95d3ffab0b9a08\
             7923809e6172eeecb7c1b2419a115ee5",
        ),
        (
            512,
            243,
            "2c2c515a40185fa3ac7370ddccf3d9f289a81565f3ed83db27ca839022310803\
             583fe52211d898fefe95d3ffab0b9a087923809e6172eeecb7c1b2419a115ee5",
        ),
        (
            384,
            244,
            "1014d7726f89e2cd5533b3f4ba040c1cf89ab81d1b1af33f3c9a16ddfbbb17f7\
             df791f4eab0b8d6e72d00f61a62f9b26",
        ),
        (
            512,
            244,
            "1b1dd9ca15af697a750efcdc023cde251014d7726f89e2cd5533b3f4ba040c1c\
             f89ab81d1b1af33f3c9a16ddfbbb17f7df791f4eab0b8d6e72d00f61a62f9b26",
        ),
    ] {
        assert_eq!(
            counting_digest(bit_length, len),
            expected,
            "DSTU 7564-{bit_length} of {len} bytes"
        );
    }
}

#[test]
fn dstu7564_matches_bouncy_castle_on_a_million_a_bytes() {
    for (bit_length, expected) in [
        (
            256,
            "090389ecc4d0b6823565d76f3d1b6dec8e6d9c08c06e59187b82f9524ae1a7bd",
        ),
        (
            384,
            "843597da19aa0497074e77d60b2a149f30cbf3dd165f75b7d3f85dee74da85c4\
             73135112f24330b5370e347ed13d0743",
        ),
        (
            512,
            "157bea93215a1f7b9b5e6bcdd9ab665c843597da19aa0497074e77d60b2a149f\
             30cbf3dd165f75b7d3f85dee74da85c473135112f24330b5370e347ed13d0743",
        ),
    ] {
        let mut digest = Dstu7564Digest::new(bit_length);
        for _ in 0..1000 {
            digest.update(&[b'a'; 1000]);
        }
        assert_eq!(
            hex_digest(&mut digest, b""),
            expected,
            "DSTU 7564-{bit_length}"
        );
    }
}
