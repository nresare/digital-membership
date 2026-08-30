# digital-membership

`digital-membership` is a small Axum service that creates signed Digital Membership
credentials and returns them directly encoded in PNG QR codes. It generates a fresh
BLS12-381 key pair each time it starts; restarting the process therefore invalidates
credentials unless verifiers also update the trusted public key.

## Run

All settings live in a TOML config file. The only command line option is the path to
it, which defaults to `/config/digital-membership.toml` so that a container deployment
can mount a ConfigMap and pass no arguments at all:

```bash
cargo run -- --config-file digital-membership.toml
```

```toml
bind_address = "127.0.0.1:8080"
name_model = "/path/to/names.ncmp"
```

`bind_address` defaults to `0.0.0.0:8080`. `name_model` is required and must identify a
model table produced for the [`namecompress`](https://github.com/nresare/namecompress)
crate. The model may be uncompressed or XZ-compressed; compression is detected from the
file contents. The service loads and validates the model at startup. Verifiers need the
same separately distributed model to decode names from credentials.

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
and matches the `algorithm` reported by `/api/provision`. The draft specifies the
identifier and the signature scheme, but neither a secret key serialisation nor a
container format, so the container above is this project's own: `secret_key` is the
32-byte scalar in unpadded URL-safe Base64, the same alphabet as the public key.

Naming the ciphersuite means a key belonging to a different BLS scheme — a different
curve, a different hash, or the augmented or proof-of-possession variants — is rejected
with a clear error rather than silently producing signatures no verifier accepts.

Keeping the file text means the key survives being pasted into a Secret manifest or
copied between systems, and can be inspected without a hex dump.

The public key is printed to stdout as the 96-byte compressed G2 point in unpadded
URL-safe Base64 — the same encoding `/api/provision` reports — so it can be captured
directly:

```bash
public_key=$(digital-membership --key-gen)
```

Diagnostics go to stderr, leaving stdout to carry only the key.

## API

### Generate a QR code

`POST /api/qr` accepts JSON with a required `name` and an optional array of numeric
`flags`:

```bash
curl -sS http://127.0.0.1:8080/api/qr \
  -H 'content-type: application/json' \
  -d '{"name":"Alice","flags":[0,5,9]}' \
  --output membership.png
```

For easy use in a web browser, `GET /api/qr` accepts the same values as URL-encoded
query parameters. Flags may be repeated or supplied as a comma-separated list:

```text
http://127.0.0.1:8080/api/qr?name=Alice%20Smith&flags=0,5,9
http://127.0.0.1:8080/api/qr?name=Alice%20Smith&flags=0&flags=5&flags=9
```

The `flags` parameter may be omitted entirely when no flags are asserted.

The response is a 768 × 768 grayscale PNG. The signed credential is placed directly in
QR byte mode using the binary layout in [`specification.md`](specification.md). Names
are compressed with the configured `namecompress` model before signing. Duplicate flag
numbers are harmless. The highest supported flag number is 2039, which corresponds to
the specification's 255-byte flag-data limit.

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

Once configured, `GET /api/wallet` accepts the same query parameters as `GET /api/qr`:

```text
https://example.com/api/wallet?name=Alice%20Smith&flags=0,5,9
```

It returns a signed `application/vnd.apple.pkpass` download. Opening the URL in Safari
on an iPhone presents the pass for addition to Apple Wallet. Wallet renders the QR code
from the same binary credential used by `/api/qr`; the pass does not contain a separate
QR image. Generated passes currently use a plain built-in placeholder icon and do not
support push updates.

If Wallet support is not configured, the endpoint returns HTTP 503. In a production
deployment, avoid putting personal details directly in a URL: use an authenticated,
opaque enrollment URL that resolves to the name and flags on the server.

### Read scanner configuration

`GET /api/provision` returns the current startup-generated verification key and the
location of the name model needed to decode credentials:

```json
{
  "algorithm": "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_",
  "key_id": 0,
  "name_model_id": 1234567890,
  "name_model_url": "/api/model/model.ncmp.xz",
  "public_key": "<base64url without padding>"
}
```

`public_key` is the 96-byte compressed BLS12-381 G2 public key encoded with unpadded
URL-safe Base64. Credentials contain 48-byte compressed G1 signatures and use key ID
`0`. `name_model_id` is the fingerprint embedded in the loaded `namecompress` model;
verifiers can use it to confirm that the model associated with this key is the expected
one.

`name_model_url` is relative to the service origin. `GET /api/model/model.ncmp.xz`
returns the validated model as an XZ-compressed `application/x-xz` response. The
downloaded model's fingerprint after decompression will match `name_model_id`. An
uncompressed startup model is compressed once when the service starts.

### Health check

`GET /api/healthz` returns HTTP 200 while the service is running.
