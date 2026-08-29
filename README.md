# digital-membership

`digital-membership` is a small Axum service that creates signed Digital Membership
credentials and returns them directly encoded in PNG QR codes. It generates a fresh
Ed25519 key pair each time it starts; restarting the process therefore invalidates
credentials unless verifiers also update the trusted public key.

## Run

```bash
cargo run -- --bind-address 127.0.0.1:8080
```

## API

### Generate a QR code

`POST /qr` accepts JSON with a required `name` and an optional array of numeric `flags`:

```bash
curl -sS http://127.0.0.1:8080/qr \
  -H 'content-type: application/json' \
  -d '{"name":"Alice","flags":[0,5,9]}' \
  --output membership.png
```

For easy use in a web browser, `GET /qr` accepts the same values as URL-encoded query
parameters. Flags may be repeated or supplied as a comma-separated list:

```text
http://127.0.0.1:8080/qr?name=Alice%20Smith&flags=0,5,9
http://127.0.0.1:8080/qr?name=Alice%20Smith&flags=0&flags=5&flags=9
```

The `flags` parameter may be omitted entirely when no flags are asserted.

The response is a 768 × 768 grayscale PNG. The signed credential is placed directly in
QR byte mode using the binary layout in [`specification.md`](specification.md). Duplicate
flag numbers are harmless. The highest supported flag number is 2039, which corresponds
to the specification's 255-byte flag-data limit.

Names must contain 1–255 UTF-8 bytes and may not contain control characters.

### Read the public key

`GET /public-key` returns the current startup-generated verification key:

```json
{
  "algorithm": "Ed25519",
  "key_id": 0,
  "public_key": "<base64url without padding>"
}
```

`public_key` is the raw 32-byte Ed25519 public key encoded with unpadded URL-safe Base64.
Generated credentials use key ID `0`.

### Health check

`GET /healthz` returns HTTP 200 while the service is running.
