# digital-membership

`digital-membership` is a small Axum service that creates signed Digital Membership
credentials and returns them directly encoded in PNG QR codes. It signs on behalf of one
or more configured issuers, each with its own BLS12-381 key, `namecompress` model and set
of flags, served under its own path.

## Run

All settings live in a TOML config file. The only command line option is the path to
it, which defaults to `/config/digital-membership.toml` so that a container deployment
can mount a ConfigMap and pass no arguments at all:

```bash
cargo run -- --config-file digital-membership.toml
```

```toml
bind_address = "127.0.0.1:8080"

[[issuer]]
id = "example"
name = "Example Membership Society"
description = "Members of the society, in good standing"
signing_key_path = "/path/to/example.secret"
name_model = "/path/to/names.ncmp"
flags = ["member", "committee", "vegetarian"]
```

`bind_address` defaults to `0.0.0.0:8080`. At least one `[[issuer]]` block is required.

### Issuers

Each issuer is served under `/api/{id}/`, so the block above answers on
`/api/example/qr`, `/api/example/wallet` and `/api/example/provision`. Configure a second
`[[issuer]]` block to sign for another organisation from the same process; the issuers
share nothing but the listening socket and the Wallet identity.

| Key | Required | Meaning |
|---|---|---|
| `id` | yes | Short identifier used as a URL path segment. ASCII letters, digits, `-` and `_` only, and unique across the file. |
| `name` | yes | Human-readable name, published by the issuer's provisioning endpoint so a scanner can show whose credential it is checking. |
| `description` | no | A brief description of the issuer, published alongside the name as supporting detail. Left out of the responses when it is not configured. |
| `signing_key_path` | yes | Path to a signing key written by `--key-gen`. Loaded and validated at startup. |
| `name_model` | yes | Path to a [`namecompress`](https://github.com/nresare/namecompress) model table, uncompressed or XZ-compressed; compression is detected from the file contents. Verifiers need the same model to decode names, and can fetch it from the issuer's model endpoint. |
| `flags` | no | Labels for this issuer's flags, where position in the list is the flag number. |

Flag labels are how a caller names a flag without hard-coding its number, and how a
scanner learns what a credential asserts. `flags = ["member", "committee"]` makes
`member` flag 0 and `committee` flag 1. An empty string leaves a number unnamed while
keeping the ones after it in place, which is how a retired flag is retained:

```toml
flags = ["member", "", "vegetarian"]
```

Never reorder or delete an entry. Flag numbers are baked into credentials already issued
and into the specification's rule that a flag number, once assigned, is never reused for
a different meaning; shifting the list silently changes what an existing credential says.
A label that reads as a number is rejected at startup, since `flags=7` would otherwise be
ambiguous between a label and a flag number.

The key and model of every issuer are loaded and validated at startup, so a missing file,
a key belonging to another ciphersuite, or an unreadable model stops the service rather
than failing on the first request.

Unknown keys are rejected, so a misspelled setting fails at startup rather than being
silently ignored. [`digital-membership.toml`](digital-membership.toml) in this
repository is a commented example of every available setting.

## Generate a signing key

`--key-gen` writes a new BLS12-381 signing key and prints its public key, then exits
without starting the service:

```bash
digital-membership --key-gen
```

The key is written to `signing-key.secret` in the current directory, or to a path given
as `--key-gen <PATH>`, and the file is created with `0600` permissions. An existing file
is never overwritten, since replacing a key silently invalidates every credential issued
under it; remove it first if that is what you want.

The file is a self-describing ASCII TOML document naming the scheme the key belongs to:

```toml
# digital-membership signing key. Treat this file as a secret.
# ciphersuite identifiers are defined by draft-irtf-cfrg-bls-signature.
ciphersuite = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
secret_key = "q7Jv0YfLpXn2wKcE4tRm9BdSaZhU1oGxN6iTlC3ePkA"
```

`ciphersuite` is the identifier defined by
[draft-irtf-cfrg-bls-signature](https://datatracker.ietf.org/doc/draft-irtf-cfrg-bls-signature/),
and matches the `algorithm` reported by the provisioning endpoint. The draft specifies the
identifier and the signature scheme, but neither a secret key serialisation nor a
container format, so the container above is this project's own: `secret_key` is the
32-byte scalar in unpadded URL-safe Base64, the same alphabet as the public key.

Naming the ciphersuite means a key belonging to a different BLS scheme — a different
curve, a different hash, or the augmented or proof-of-possession variants — is rejected
with a clear error rather than silently producing signatures no verifier accepts.

Keeping the file text means the key survives being pasted into a Secret manifest or
copied between systems, and can be inspected without a hex dump.

Point an issuer's `signing_key_path` at the file it writes.

The public key is printed to stdout as the 96-byte compressed G2 point in unpadded
URL-safe Base64 — the same encoding the provisioning endpoint reports — so it can be
captured directly:

```bash
public_key=$(digital-membership --key-gen)
```

Diagnostics go to stderr, leaving stdout to carry only the key.

## API

### Generate a QR code

`POST /api/{issuer}/qr` accepts JSON with a required `name`, an optional array of
`flags`, and an optional member identifier:

```bash
curl -sS http://127.0.0.1:8080/api/example/qr \
  -H 'content-type: application/json' \
  -d '{"name":"Alice","flags":["member","vegetarian"],"member_number":4242}' \
  --output membership.png
```

For easy use in a web browser, `GET /api/{issuer}/qr` accepts the same values as
URL-encoded query parameters. Flags may be repeated or supplied as a comma-separated
list:

```text
http://127.0.0.1:8080/api/example/qr?name=Alice%20Smith&flags=member,vegetarian&member_number=4242
http://127.0.0.1:8080/api/example/qr?name=Alice%20Smith&flags=0&flags=5&flags=9
```

A flag may be named by its label or by its number, and the two may be mixed. A label the
issuer does not define is rejected with HTTP 400, so a typo fails loudly instead of
asserting the wrong flag; a bare number is always taken at face value, which is how a
flag with no label is asserted. The `flags` parameter may be omitted entirely when no
flags are asserted. A path naming an issuer that is not configured returns HTTP 404.

The member identifier is an opaque handle the issuer assigns; the credential carries it
so a scanner can recognise a member across re-issued codes, and so that a revocation
list can name one. It comes in two forms, at most one of which may be given:

- `member_number`, an integer below 2^48, stored in one to six bytes.
- `member_id`, 1–255 UTF-8 bytes without control characters, stored with a length byte.

Prefer `member_number` for identifiers that are already numeric: it is smaller. Omit
both when no identifier is needed, which costs nothing in the credential.

Each credential also records the UTC day it was signed, which a scanner can use to
reject codes older than some age of its choosing. The day is written into 13 bits
counted from `2026-01-01`, so it stops being representable after `2048-06-05`.

The response is a 768 × 768 grayscale PNG. The signed credential is placed directly in
QR byte mode using the binary layout in [`specification.md`](specification.md). Names
are compressed with the configured `namecompress` model before signing. Duplicate flag
numbers are harmless. The highest supported flag number is 2042: three flags ride in the
header, and the rest fit the specification's 255-byte flag-data limit.

Names must contain 1–255 UTF-8 bytes and may not contain control characters.

### Generate an Apple Wallet pass

Wallet support is optional. Configure it with a Pass Type signing identity exported as
PKCS#12, the Apple Worldwide Developer Relations intermediate certificate, and the
identifiers from the Apple Developer portal:

```toml
[wallet]
pkcs12 = "/path/to/pass-identity.p12"
wwdr_certificate = "/path/to/AppleWWDR.cer"
pass_type_identifier = "pass.example.digital-membership"
team_identifier = "ABCDE12345"
organization_name = "Example Membership"
```

Omit the whole `[wallet]` section to disable Wallet support; within it, every key other
than `organization_name` is required. `organization_name` defaults to `Digital
Membership`. The certificate may be PEM or DER.

Export the PKCS#12 identity without a password. The file holds the Pass Type private
key, so it is the secret in its own right and must be mounted from a Kubernetes Secret
rather than a ConfigMap; wrapping it in a second secret that has to be deployed
alongside it protects nothing.

The Wallet identity is configured once and shared by every issuer.

Once configured, `GET /api/{issuer}/wallet` accepts the same query parameters as
`GET /api/{issuer}/qr`:

```text
https://example.com/api/example/wallet?name=Alice%20Smith&flags=member,vegetarian
```

It returns a signed `application/vnd.apple.pkpass` download. Opening the URL in Safari
on an iPhone presents the pass for addition to Apple Wallet. Wallet renders the QR code
from the same binary credential used by the QR endpoint; the pass does not contain a separate
QR image. Generated passes currently use a plain built-in placeholder icon and do not
support push updates.

If Wallet support is not configured, the endpoint returns HTTP 503. In a production
deployment, avoid putting personal details directly in a URL: use an authenticated,
opaque enrollment URL that resolves to the name, flags, and member identifier on the
server.

### Bootstrap a scanner

`GET /setup` lists the issuers this instance signs for:

```json
{
  "issuers": [
    {
      "id": "example",
      "name": "Example Membership Society",
      "description": "Members of the society, in good standing",
      "provision_url": "/api/example/provision"
    },
    {
      "id": "choir",
      "name": "Example Choral Society",
      "provision_url": "/api/choir/provision"
    }
  ]
}
```

This is the one endpoint a scanner can reach knowing nothing but the service origin, which is why it sits outside `/api` rather than under an issuer path. Point a scanner at `https://example.com/setup`, show the `name` of each entry, and fetch the `provision_url` of whichever the user picks to get that issuer's key, model and flag labels. `provision_url` is relative to the service origin.

Issuers are listed in order of `id`, not in the order they appear in the config file, so the list is stable across edits.

### Read scanner configuration

`GET /api/{issuer}/provision` returns everything a scanner needs to verify and display
that issuer's credentials:

```json
{
  "algorithm": "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_",
  "id": "example",
  "name": "Example Membership Society",
  "description": "Members of the society, in good standing",
  "name_model_id": 1234567890,
  "name_model_url": "/api/example/model/model.ncmp.xz",
  "public_key": "<base64url without padding>",
  "flags": ["member", "", "vegetarian"]
}
```

`public_key` is the 96-byte compressed BLS12-381 G2 public key encoded with unpadded
URL-safe Base64. Credentials contain 48-byte compressed G1 signatures. `name` is
what a scanner shows to say whose membership it is checking, `description` is optional
supporting detail and absent when the issuer configures none, and `flags` gives it the
name of each flag a credential can assert, indexed by flag number, with an empty string
where a number has no label.

`name_model_id` is the fingerprint embedded in the loaded `namecompress` model; verifiers
can use it to confirm that the model associated with this key is the expected one.
`name_model_url` is relative to the service origin and returns the validated model as an
XZ-compressed `application/x-xz` response, whose fingerprint after decompression will
match `name_model_id`. An uncompressed startup model is compressed once at startup.

Nothing in a credential says which issuer signed it. A scanner is provisioned from one
issuer's endpoint and verifies against the key it was given there.

### Health check

`GET /healthz` returns HTTP 200 while the service is running.

## Issue a credential from a browser

`GET /test` serves a small HTML form for issuing a credential by hand, which is enough
to try an issuer out without a client that speaks the API. Pick the issuer, type a name
and an optional id, tick the flags to assert and press **generate**; the result page
shows the credential as a QR code, along with what went into it.

Only labelled flags get a checkbox, since an unlabelled number has nothing to show. An
id of plain digits is carried as a number, which encodes more compactly; anything a
number would not preserve, such as the leading zeros of `007`, is carried as text.

The form has no authentication in front of it and will issue a credential to whoever
asks, exactly as `/api/{issuer}/qr` does. Keep the service off the public internet, or
behind something that authenticates, if that matters.
