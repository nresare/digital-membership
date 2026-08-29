# digital-membership

`digital-membership` is a small Axum service that creates signed Digital Membership
credentials and returns them directly encoded in PNG QR codes. It generates a fresh
BLS12-381 key pair each time it starts; restarting the process therefore invalidates
credentials unless verifiers also update the trusted public key.

## Run

```bash
cargo run -- \
  --bind-address 127.0.0.1:8080 \
  --name-model /path/to/names.ncmp
```

`--name-model` is required and must identify a model table produced for the
[`namecompress`](https://github.com/nresare/namecompress) crate. The model may be
uncompressed or XZ-compressed; compression is detected from the file contents. The
service loads and validates the model at startup. Verifiers need the same separately
distributed model to decode names from credentials.

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
