//! Official FIPS 202 SHAKE known-answer tests, extracted from bc-csharp
//! `crypto/test/data/crypto/SHAKETestVectors.txt` (byte-aligned samples only:
//! the 0-bit empty message and the 1600-bit message = 200 x 0xA3). Each output
//! is 512 bytes, exercising multi-block squeezing across the sponge rate.

use tc_digest::{Digest, Xof};
use tc_keccak::ShakeDigest;

fn unhex(s: &str) -> Vec<u8> {
    // The literals wrap with `\n` and indentation, so keep only the hex digits.
    let digits: Vec<char> = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    digits
        .chunks(2)
        .map(|pair| {
            let hi = pair[0].to_digit(16).unwrap() as u8;
            let lo = pair[1].to_digit(16).unwrap() as u8;
            (hi << 4) | lo
        })
        .collect()
}

/// `(bit_length, message, 512-byte output hex)`.
const VECTORS: &[(usize, &[u8], &str)] = &[
    (
        128,
        &[],
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26\n         3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2\n         35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2\n         badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea\n         17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdef\n         aee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d\n         ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9\n         22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619\n         f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b\n         1de33fd75081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f\n         1368ec2967fc84ef2ae9aff268e0b1700affc6820b523a3d917135f2dff2ee06\n         bfe72b3124721d4a26c04e53a75e30e73a7a9c4a95d91c55d495e9f51dd0b5e9\n         d83c6d5e8ce803aa62b8d654db53d09b8dcff273cdfeb573fad8bcd45578bec2\n         e770d01efde86e721a3f7c6cce275dabe6e2143f1af18da7efddc4c7b70b5e34\n         5db93cc936bea323491ccb38a388f546a9ff00dd4e1300b9b2153d2041d205b4\n         43e41b45a653f2a5c4492c1add544512dda2529833462b71a41a45be97290b6f",
    ),
    (
        128,
        &[0xA3u8; 200],
        "131ab8d2b594946b9c81333f9bb6e0ce75c3b93104fa3469d3917457385da037\n         cf232ef7164a6d1eb448c8908186ad852d3f85a5cf28da1ab6fe343817197846\n         7f1c05d58c7ef38c284c41f6c2221a76f12ab1c04082660250802294fb871802\n         13fdef5b0ecb7df50ca1f8555be14d32e10f6edcde892c09424b29f597afc270\n         c904556bfcb47a7d40778d390923642b3cbd0579e60908d5a000c1d08b98ef93\n         3f806445bf87f8b009ba9e94f7266122ed7ac24e5e266c42a82fa1bbefb7b8db\n         0066e16a85e0493f07df4809aec084a593748ac3dde5a6d7aae1e8b6e5352b2d\n         71efbb47d4caeed5e6d633805d2d323e6fd81b4684b93a2677d45e7421c2c6ae\n         a259b855a698fd7d13477a1fe53e5a4a6197dbec5ce95f505b520bcd9570c4a8\n         265a7e01f89c0c002c59bfec6cd4a5c109258953ee5ee70cd577ee217af21fa7\n         0178f0946c9bf6ca8751793479f6b537737e40b6ed28511d8a2d7e73eb75f8da\n         ac912ff906e0ab955b083bac45a8e5e9b744c8506f37e9b4e749a184b30f43eb\n         188d855f1b70d71ff3e50c537ac1b0f8974f0fe1a6ad295ba42f6aec74d123a7\n         abedde6e2c0711cab36be5acb1a5a11a4b1db08ba6982efccd716929a7741cfc\n         63aa4435e0b69a9063e880795c3dc5ef3272e11c497a91acf699fefee206227a\n         44c9fb359fd56ac0a9a75a743cff6862f17d7259ab075216c0699511643b6439",
    ),
    (
        256,
        &[],
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\n         d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be\n         141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853\n         349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86\n         f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d6\n         77231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5c\n         aaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea2\n         03bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f\n         5a1aaa96d313eacc890936c173cdcd0fab882c45755feb3aed96d477ff96390b\n         f9a66d1368b208e21f7c10d04a3dbd4e360633e5db4b602601c14cea737db3dc\n         f722632cc77851cbdde2aaf0a33a07b373445df490cc8fc1e4160ff118378f11\n         f0477de055a81a9eda57a4a2cfb0c83929d310912f729ec6cfa36c6ac6a75837\n         143045d791cc85eff5b21932f23861bcf23a52b5da67eaf7baae0f5fb1369db7\n         8f3ac45f8c4ac5671d85735cdddb09d2b1e34a1fc066ff4a162cb263d6541274\n         ae2fcc865f618abe27c124cd8b074ccd516301b91875824d09958f341ef274bd\n         ab0bae316339894304e35877b0c28a9b1fd166c796b9cc258a064a8f57e27f2a",
    ),
    (
        256,
        &[0xA3u8; 200],
        "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d\n         2d700caae7396ece96604440577da4f3aa22aeb8857f961c4cd8e06f0ae6610b\n         1048a7f64e1074cd629e85ad7566048efc4fb500b486a3309a8f26724c0ed628\n         001a1099422468de726f1061d99eb9e93604d5aa7467d4b1bd6484582a384317\n         d7f47d750b8f5499512bb85a226c4243556e696f6bd072c5aa2d9b69730244b5\n         6853d16970ad817e213e470618178001c9fb56c54fefa5fee67d2da524bb3b0b\n         61ef0e9114a92cdbb6cccb98615cfe76e3510dd88d1cc28ff99287512f24bfaf\n         a1a76877b6f37198e3a641c68a7c42d45fa7acc10dae5f3cefb7b735f12d4e58\n         9f7a456e78c0f5e4c4471fffa5e4fa0514ae974d8c2648513b5db494cea84715\n         6d277ad0e141c24c7839064cd08851bc2e7ca109fd4e251c35bb0a04fb05b364\n         ff8c4d8b59bc303e25328c09a882e952518e1a8ae0ff265d61c465896973d749\n         0499dc639fb8502b39456791b1b6ec5bcc5d9ac36a6df622a070d43fed781f5f\n         149f7b62675e7d1a4d6dec48c1c7164586eae06a51208c0b791244d307726505\n         c3ad4b26b6822377257aa152037560a739714a3ca79bd605547c9b78dd1f596f\n         2d4f1791bc689a0e9b799a37339c04275733740143ef5d2b58b96a363d4e0807\n         6a1a9d7846436e4dca5728b6f760eef0ca92bf0be5615e96959d767197a0beeb",
    ),
];

#[test]
fn official_shake_kat() {
    for &(bits, message, expected_hex) in VECTORS {
        let expected = unhex(expected_hex);
        // Read at once.
        let mut d = ShakeDigest::new(bits);
        d.update(message);
        let mut out = vec![0u8; expected.len()];
        d.output_final(&mut out);
        assert_eq!(out, expected, "SHAKE{bits} single-shot");
        // Read in two pieces, the same stream.
        let mut d = ShakeDigest::new(bits);
        d.update(message);
        let mut out = vec![0u8; expected.len()];
        let half = out.len() / 2;
        let (a, b) = out.split_at_mut(half);
        d.output(a);
        d.output(b);
        assert_eq!(out, expected, "SHAKE{bits} split");
    }
}
