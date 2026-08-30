# Digital Membership Binary Format

Draft version 0.5

## 1. Purpose

Digital Membership is a compact, self-contained credential intended for carriage in a QR code and offline verification.

Version 1 authenticates:

- A member’s display name
- The day the credential was signed
- An optional opaque member identifier
- A variable-length set of externally defined flags

Names are encoded with `namecompress` against a separately distributed model. Credentials use BLS signatures over BLS12-381 in the minimal-signature-size variant.

## 2. Binary representation

```text
+--------+----------+----------+------------+-----------+-----------------+---------------+
| Header | Extended | Issuance | Member     | Flag data | Compressed name | BLS signature |
|        | length?  | word     | identifier |           |                 |               |
| 1 byte | 0 or 1   | 2 bytes  | I bytes    | F bytes   | C bytes         | 48 bytes      |
+--------+----------+----------+------------+-----------+-----------------+---------------+
```

The extended-length byte is present only when indicated by the header.

Every variable-length field except the compressed name is preceded by its own length or size code, so all field boundaries are known before the name is reached.

No compressed-name-length field is encoded. The compressed name extends from the end of the flag data to the beginning of the fixed-length signature.

## 3. Header

```text
  7         5 4         2 1         0
 +-----------+-----------+-----------+
 | Version   | Key ID    | Flag size |
 +-----------+-----------+-----------+
```

### Version

Bits 7–5 contain the format version. Version 1 is encoded as `001`.

Version zero is reserved.

Version 1 is not yet frozen. Until it is, this document may change what a version 1 credential contains without allocating a new version number, and an issuer and verifier pair MUST be built from the same draft.

### Key ID

Bits 4–2 contain a Key ID from 0 through 7. The identifier selects an issuer configuration containing both a compressed BLS12-381 G2 public key and a `namecompress` model. Both are configured out of band in the verifier.

### Flag-size code

Bits 1–0 encode the number of flag bytes:

| Code | Meaning |
|---|---|
| `00` | No flag bytes |
| `01` | One flag byte |
| `10` | Two flag bytes |
| `11` | Extended length follows |

When the code is `11`, the byte immediately following the header contains the number of flag bytes. Its value MUST be between 3 and 255 inclusive.

Encodings MUST use the shortest representation. An extended length of 0, 1, or 2 is invalid.

## 4. Issuance word

The issuance word is two bytes, interpreted as a big-endian 16-bit value:

```text
  15                                 3 2         0
 +-------------------------------------+---------+
 | Issue day                           | ID code |
 +-------------------------------------+---------+
```

### Issue day

Bits 15–3 contain a 13-bit count of days since the epoch `2026-01-01T00:00:00Z`, which is Unix time 1767225600, or Unix day 20454. The epoch day itself is zero. The largest representable value, 8191, is `2048-06-05`.

The count is defined directly on Unix time, so no calendar arithmetic is needed in either direction. From a Unix timestamp `t` in seconds:

```text
issue_day = floor(t / 86400) - 20454
```

And back again, to the first second of that day:

```text
t = (issue_day + 20454) * 86400
```

Unix time excludes leap seconds, so every day is exactly 86400 seconds long and the integer division above is exact. Timestamps before the epoch make the subtraction negative, and are not representable.

The issue day is the UTC day on which the credential was signed. An issuer MUST NOT backdate or postdate it.

A verifier MUST reject a credential whose issue day is more than one day in the future, which allows for clock skew and for a scanner in a timezone ahead of the issuer. A verifier SHOULD reject a credential older than a locally configured maximum age. The format defines no expiry of its own: the issue day is the input to a verifier’s freshness policy, not a statement of validity by the issuer.

### ID code

Bits 2–0 select the form of the member identifier that follows the issuance word:

| Code | Meaning |
|---|---|
| `0` | No member identifier; `I` is zero |
| `1`–`6` | Integer identifier stored in the next `code` bytes |
| `7` | Text identifier; a length byte follows |

## 5. Member identifier

The member identifier is an opaque handle for the member, assigned by the issuer. It carries no structure this specification defines, and a verifier MUST NOT parse, split, or otherwise interpret it beyond comparing it for equality with identifiers it already holds.

### Integer form

When the ID code is 1 through 6, the identifier is that many bytes, holding an unsigned big-endian integer. The representable range is therefore 0 through 2^48 − 1.

The encoding MUST be the shortest one that holds the value: for any identifier other than zero the first byte MUST be nonzero. The value zero is encoded with ID code 1 and the single byte `00`.

### Text form

When the ID code is 7, a single length byte follows the issuance word, holding a value between 1 and 255 inclusive. That many bytes of identifier text follow it.

The identifier text MUST be valid UTF-8 and MUST NOT contain control characters. A verifier MUST reject a credential whose identifier text is not valid UTF-8, and MUST NOT normalize or otherwise modify it. An empty text identifier is invalid; a credential with no identifier MUST use ID code 0.

Because the text form costs a length byte, an identifier that is a decimal number SHOULD be carried in the integer form, which is smaller for every value above 99999999999999.

### Choosing an identifier

The identifier is intended to support revocation and to let a verifier recognise a member across re-issued credentials. Issuers that mint identifiers without a central counter should note that a randomly chosen identifier needs enough width to make collisions unlikely: at `n` bits, collisions become likely at around 2^(n/2) members.

## 6. Flags

Flags are represented as a little-endian bitset.

Flag number `k` is stored in:

```text
byte index = floor(k / 8)
bit index  = k modulo 8
```

Bit zero is the least significant bit of the first flag byte.

For example:

```text
Flag data: 21 02

21 = 00100001  → flags 0 and 5
02 = 00000010  → flag 9
```

Thus, this example asserts flags 0, 5, and 9.

Flag data MUST use its minimum possible length. When flag data is present, its final byte MUST be nonzero. A zero-valued flag set MUST be represented using zero flag bytes.

The meaning of each flag is defined by an external issuer profile. Once assigned, a flag number MUST NOT be reused for a different meaning.

Unknown flags MAY be ignored, but MUST NOT cause a verifier to grant an authorization it does not understand.

## 7. Compressed name

The compressed-name field consists of every byte following the flag data and preceding the final 48-byte signature. These bytes are a `namecompress` message and are not UTF-8.

Before compression, the display name:

- MUST contain between 1 and 255 bytes.
- MUST be valid UTF-8.
- SHOULD use Unicode Normalization Form C.
- MUST NOT contain control characters.
- MUST be encoded exactly as intended for display.

The encoder MUST encode the exact display-name string with `namecompress::compress` and the model associated with the Key ID. The model's fingerprint is its `name_model_id` and SHOULD be distributed with the issuer's public-key metadata.

A verifier MUST use the model associated with the Key ID to decompress the field. Decompression failure, including a `namecompress` wrong-table check, makes the credential invalid. A verifier MUST NOT normalize or modify the decompressed name. It MUST validate and display the name only after successful signature verification and decompression.

## 8. Signature

BLS signatures are used as specified in [draft-irtf-cfrg-bls-signature](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/).

The ciphersuite is the Basic scheme over BLS12-381 using SHA-256 and the minimal-signature-size variant:

```text
BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_
```

Signatures MUST use the canonical 48-byte compressed representation of a point in G1. Public keys MUST use the canonical 96-byte compressed representation of a point in G2.

The fixed domain-separation prefix is the following ASCII byte string, including the terminating zero byte:

```text
digital-membership/v1\x00
```

The prefix is versioned, so a credential of one format version can never verify under the rules of another.

Let `unsigned_credential` be every transmitted byte except the trailing signature:

```text
header || extended_flag_length? || issuance_word || member_identifier || flags || compressed_name
```

The signed message is:

```text
"digital-membership/v1\x00" || unsigned_credential
```

The complete credential is:

```text
unsigned_credential || BLS.Sign(private_key, signed_message)
```

The domain-separation prefix is not transmitted.

## 9. Parsing

Given a credential containing `L` bytes, a verifier MUST:

1. Reject it if `L < 51`.
2. Interpret the final 48 bytes as the signature.
3. Decode the header and reject any version other than 1.
4. Determine the flag-data length.
5. Reject non-minimal or out-of-bounds flag encodings.
6. Decode the issuance word into an issue day and an ID code.
7. Determine the member-identifier length from the ID code and, for the text form, its length byte.
8. Reject a non-minimal integer identifier, a zero-length text identifier, or a text identifier that is not valid UTF-8.
9. Interpret the flag bytes as a bitset.
10. Treat all remaining unsigned bytes as the compressed name.
11. Resolve the Key ID to a trusted public key and `namecompress` model, and validate that the public key is a canonical, non-identity point in the correct subgroup of G2.
12. Validate that the signature is a canonical, non-identity point in the correct subgroup of G1.
13. Verify the signature over the domain prefix and unsigned credential using the specified ciphersuite.
14. Decompress the name with the model associated with the Key ID and reject any decompression error.
15. Reject an issue day more than one day in the future, and apply the locally configured maximum age.
16. Validate and display the decompressed name only after successful verification.

All arithmetic and bounds checks MUST be completed before slicing the input.

## 10. Size

The credential size is:

```text
1 + E + 2 + I + F + C + 48 bytes
```

Where:

- `E` is 1 for extended flag lengths and otherwise 0.
- `I` is the member-identifier length: 0 with no identifier, 1 to 6 for the integer form, and 1 plus the text length for the text form.
- `F` is the number of flag bytes.
- `C` is the compressed-name length.

For example, a name that compresses to six bytes, with two flag bytes and a two-byte integer identifier, produces:

```text
1 + 0 + 2 + 2 + 2 + 6 + 48 = 61 bytes
```

QR byte mode at error correction level M holds 62 bytes in a version 3 symbol and 84 bytes in a version 4 symbol. Issuers who want to stay within a 29×29 module symbol have a budget of 62 bytes for the whole credential, which the fixed 51 bytes of overhead leave 11 bytes of.

## 11. Example

Suppose:

- Version is 1.
- Key ID is 2.
- The credential is signed on `2026-08-30`, which is day 241.
- The member identifier is the integer 4242, which needs two bytes.
- One flag byte is present.
- Flags 0 and 5 are asserted.
- The name is `John Smith`.
- The configured `namecompress` model encodes it as `C[0]` through `C[n-1]`.

The header is:

```text
001 010 01 = 0x29
```

The issuance word is day 241 shifted left by three bits, with ID code 2:

```text
(241 << 3) | 2 = 1930 = 0x078A
```

The unsigned credential is:

```text
29 07 8A 10 92 21 C[0] ... C[n-1]
│  │     │     │  └────────────── compressed `namecompress` message
│  │     │     └───────────────── flags 0 and 5
│  │     └─────────────────────── member identifier 4242
│  └───────────────────────────── issue day 241, ID code 2
└──────────────────────────────── version 1, key 2, one flag byte
```

The 48-byte compressed BLS signature follows these bytes.

The complete credential is `6 + n + 48` bytes.

## 12. QR transport

Where supported, the credential SHOULD be placed directly into a QR code using byte mode.

Text armoring required by another transport is a separate encoding layer and is not part of this specification.

## 13. Security and privacy considerations

The signature authenticates the compressed name, issue day, member identifier, and flags, but provides no confidentiality. Compression is not encryption: anyone who obtains the QR code and the separately distributed model can recover the display name and flags. The issue day and member identifier are in clear view of any scanner.

Dietary requirements, political affiliations, protected-group membership, and similar flags may constitute sensitive personal information. Issuers should include only information required at the point of scanning.

The member identifier is stable across re-issued credentials, which is what makes revocation and recognition possible, and also what makes every scan of the same member linkable to every other by anyone who can read the code. An issuer that does not need to recognise a member across credentials should omit the identifier. An identifier that encodes something about the member, such as a joining sequence or a national identity number, discloses that to every scanner and should not be used.

The issue day narrows the window in which a leaked credential is useful, but only to the extent that a verifier enforces a maximum age. It is not an expiry: a verifier that ignores it accepts an arbitrarily old credential.

Version 1 does not provide:

- Bearer identity verification
- An issuer-asserted validity period
- Online revocation
- Event restriction
- Protection against copying or screenshot sharing

The member identifier makes an offline revocation list possible, but distributing one is out of scope for this document.
