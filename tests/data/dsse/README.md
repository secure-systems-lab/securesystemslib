# DSSE cross-language fixtures

`cross_lang_signing.json` is an unchanged copy of the public fixture file at
[`probityai/dsse` commit `f6f6df4bef5544af76dc3f5b05909a2f24a8e51f`](https://github.com/probityai/dsse/blob/f6f6df4bef5544af76dc3f5b05909a2f24a8e51f/vectors/cross_lang_signing.json).
Its SHA-256 is
`f5f6c8e991ecb452d73b6289eef8632666dbb50c7f1ef25827b28e869e16152c`.

The producer used the reference Go DSSE implementation at
`github.com/secure-systems-lab/go-securesystemslib/dsse` version `v0.11.1`,
as recorded in the file. The eleven cases include empty and binary payloads,
Unicode payload bytes, and a payload type whose UTF-8 byte count differs from
its character count. Each case includes the PAE bytes, an Ed25519 signature,
and the complete envelope. The published seed is a test key.

`tests/test_dsse.py` checks the fixture digest before any case runs. It checks
PAE byte identity, native signature verification, deterministic native signing,
and refusals for changed payloads, types, signatures and keys. The wrong-key
test preserves the key identifier to reach cryptographic verification.
The tests use local data and need no signing service or transparency log.

The non-ASCII case uses the UTF-8 byte length that the DSSE protocol defines.
Old signatures over a character-length preimage are not protocol signatures.
The explicit negative test refuses that preimage. ASCII payload types keep
their existing signing bytes. No type normalization or legacy fallback applies.
