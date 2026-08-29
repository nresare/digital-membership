# Digital Membership Binary Format

Draft version 0.3

## 1. Purpose

Digital Membership is a compact, self-contained credential intended for carriage in a QR code and offline verification.

Version 1 authenticates:

- A member’s display name
- A variable-length set of externally defined flags

It uses BLS signatures over BLS12-381 in the minimal-signature-size variant.

## 2. Binary representation

```text
+--------+------------------+-----------+------------+---------------+
| Header | Extended length? | Flag data | UTF-8 name | BLS signature |
| 1 byte | 0 or 1 byte      | F bytes   | N bytes    | 48 bytes      |
+--------+------------------+-----------+------------+---------------+
```

The extended-length byte is present only when indicated by the header.

No name-length field is encoded. The name extends from the end of the flag data to the beginning of the fixed-length signature.

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

### Key ID

Bits 4–2 contain a Key ID from 0 through 7. The identifier selects a compressed BLS12-381 G2 public key configured out of band in the verifier.

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

## 4. Flags

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

## 5. Name

The name consists of every byte following the flag data and preceding the final 48-byte signature.

The name:

- MUST contain between 1 and 255 bytes.
- MUST be valid UTF-8.
- SHOULD use Unicode Normalization Form C.
- MUST NOT contain control characters.
- MUST be encoded exactly as intended for display.

A verifier MUST NOT normalize or modify the name before verifying the signature.

## 6. Signature

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

Let `unsigned_credential` be every transmitted byte except the trailing signature:

```text
header || extended_flag_length? || flags || name
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

## 7. Parsing

Given a credential containing `L` bytes, a verifier MUST:

1. Reject it if `L < 50`.
2. Interpret the final 48 bytes as the signature.
3. Decode the header.
4. Determine the flag-data length.
5. Reject non-minimal or out-of-bounds flag encodings.
6. Interpret the flag bytes as a bitset.
7. Treat all remaining unsigned bytes as the UTF-8 name.
8. Resolve the Key ID to a trusted public key and validate that it is a canonical, non-identity point in the correct subgroup of G2.
9. Validate that the signature is a canonical, non-identity point in the correct subgroup of G1.
10. Verify the signature over the domain prefix and unsigned credential using the specified ciphersuite.
11. Validate and display the name only after successful verification.

All arithmetic and bounds checks MUST be completed before slicing the input.

## 8. Size

The credential size is:

```text
1 + E + F + N + 48 bytes
```

Where:

- `E` is 1 for extended flag lengths and otherwise 0.
- `F` is the number of flag bytes.
- `N` is the UTF-8 name length.

A 20-byte name with two flag bytes produces:

```text
1 + 0 + 2 + 20 + 48 = 71 bytes
```

## 9. Example

Suppose:

- Version is 1.
- Key ID is 2.
- One flag byte is present.
- Flags 0 and 5 are asserted.
- The name is `Alice`.

The header is:

```text
001 010 01 = 0x29
```

The unsigned credential is:

```text
29 21 41 6c 69 63 65
│  │  └───────────── UTF-8 "Alice"
│  └──────────────── flags 0 and 5
└─────────────────── version 1, key 2, one flag byte
```

The 48-byte compressed BLS signature follows these bytes.

The complete credential is 55 bytes.

## 10. QR transport

Where supported, the credential SHOULD be placed directly into a QR code using byte mode.

Text armoring required by another transport is a separate encoding layer and is not part of this specification.

## 11. Security and privacy considerations

The signature authenticates the name and flags but provides no confidentiality. Anyone who scans or photographs the QR code can read them.

Dietary requirements, political affiliations, protected-group membership, and similar flags may constitute sensitive personal information. Issuers should include only information required at the point of scanning.

Version 1 does not provide:

- Bearer identity verification
- Expiration
- Revocation
- A stable membership identifier
- Event restriction
- Protection against copying or screenshot sharing

A production revision should add a credential identifier and validity period.
