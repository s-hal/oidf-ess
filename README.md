# Entity Statement Signer for OpenID Federation 1.0

`oidf-ess` generates and publishes signed [Entity
Statements](https://openid.net/specs/openid-federation-1_0.html). It is designed
for operators of federation entities who need reliable and automated publication
at `/.well-known/openid-federation`.


## Features

- Signs Entity Statements with ES256 (or other JWS algorithms supported by
  [cryptojwt](https://github.com/IdentityPython/JWTConnect-Python-CryptoJWT))
- Reads operator-maintained metadata from JSON/YAML
- Publishes compact JWTs atomically
- Supports short-lived statements (`exp`/`iat` handling)
- Runs continuously in a container or as a one-shot signer (`--once`)
- Provides a bootstrap script to set up keys, metadata, TLS, and `.env`


## Quick start

Run the default bootstrap and start the containers.

```bash
./bootstrap.sh
docker compose up
```

Fetch the Entity Configuration JWT and save it locally.

```bash
curl -sk https://127.0.0.1/.well-known/openid-federation -o entity_configuration.jwt
```
The dev endpoint uses a self-signed TLS certificate. The -k flag tells curl to
skip certificate verification. Open the JWT in your preferred decoder. For
example, paste it into [https://jwt.io](https://jwt.io).



## Bootstrap (`./bootstrap.sh`)

The bootstrap script provisions a local working directory so the signer and
NGINX can start immediately. It is idempotent. Re-running does nothing unless
`--force` is used.


### What it does

* Creates a Python venv and installs dependencies.
* Generates EC signing keys as JWK plus a public JWKS.
* Creates a self-signed TLS certificate and key for NGINX with SANs.
* Writes a `.env` file for Docker Compose with `UID`, `GID`, and service
  variables.

### Prerequisites

* Bash, Python 3, OpenSSL, `uuidgen`
* `requirements.txt` present in the repo root
* `tools/ess_keygen.py` available and executable

### Outputs

```
secrets/
  fed-es256-private.jwk    # EC private JWK (chmod 600)
config/
  fed-es256-public.jwk     # EC public JWK
  fed-jwks.json            # JWKS with the public key
nginx/https_certs/
  https.key                # self-signed RSA private key (chmod 600)
  https.crt                # self-signed certificate
data/www/.well-known/
  openid-federation        # publish target file (touched)
.env                       # UID/GID and service variables
.venv/                     # Python virtual environment
```

### Force mode

The option `--force` causes the bootstrap to run in overwrite mode:

```bash
./bootstrap.sh --force
```

When invoked with this option, the script removes existing artifacts and
recreates them. This includes signing keys, the JWKS, the TLS certificate, and
`.env`. Existing files are not preserved.

**Warning:** Using `--force` destroys prior state. Operators MUST ensure that
dependent services reload or restart so that they consume the newly generated
artifacts.


## Configuration defaults

The following defaults apply to both the bootstrap and the signer. They can be
overridden with CLI flags or environment variables.

* **`ENTITY_ID=https://entity.example.org`** Federation entity identifier.
  Placed in `iss` and `sub`.

* **`CERT_HOSTS=entity.example.org,localhost,127.0.0.1`** Hosts used in the TLS
  certificate.

  * The **first entry** becomes the Common Name (CN).
  * All entries are added to the Subject Alternative Name (SAN).

* **`CURVE=P-256`** Elliptic curve for the signing key. Default `P-256` (ES256).
  Supported: `P-384`, `P-521`.

* **`OUT_DIR=.`** Root directory for generated files:

  * `secrets/` for private keys
  * `config/` for public config and JWKS
  * `data/www/.well-known/` for the published Entity Statement

* **`.env` contents** Written by the bootstrap. Consumed by Docker Compose:

  * **`UID` / `GID`** — user and group IDs of the caller (or shell env). Ensures
    containers run with matching ownership.
  * **`JWKS_PATH=/config/fed-jwks.json`** — path inside container to public
    JWKS.
  * **`META_PATH=/config/entity-metadata.json`** — operator-maintained metadata
    merged into the Entity Statement. Protocol metadata belongs under the
    `metadata` key.
  * **`OUTPUT_PATH=/out/.well-known/openid-federation`** — publish target path.
  * **`EXP_SECONDS=86400`** — Entity Statement validity (default 24h).
  * **`RESIGN_INTERVAL=3600`** — interval between signatures (default 1h).


## Signer (`signer.py`)

The signer generates a compact Entity Statement (`typ=entity-statement+jwt`)
using ES256 and atomically publishes it.

### Behavior

* Reads settings from CLI flags or ENV (flags take precedence)
* Performs a preflight check of paths and prints hints when files are missing
* Assembles claims: `iss`, `sub`, `iat`, `exp`, `jwks`
* Merges operator-maintained metadata from `entity-metadata.json`
* Signs with the private JWK
* Writes the compact JWS atomically to the publish target
* Runs continuously at `--resign-interval` or once with `--once`

### CLI flags

* `--entity-id` (ENV: `ENTITY_ID`) **required** if not set in ENV
* `--resign-interval` (ENV: `RESIGN_INTERVAL`, default `3600`)
* `--jwks-path` (ENV: `JWKS_PATH`, default `/config/fed-jwks.json`)
* `--meta-path` (ENV: `META_PATH`, default `/config/entity-metadata.json`)
* `--out-path` (ENV: `OUTPUT_PATH`, default
  `/out/.well-known/openid-federation`)
* `--exp-seconds` (ENV: `EXP_SECONDS`, default `86400`)
* `--priv-path` (ENV: `PRIV_PATH`, default `/run/secrets/fed-es256-private.jwk`)
* `--once` (ENV: `SIGNER_ONCE=1`)

### One-time run

Outside a container, explicit paths must be set or the bootstrap run first:

```bash
python signer.py --once \
  --entity-id https://entity.example.org \
  --jwks-path config/fed-jwks.json \
  --meta-path config/entity-metadata.json \
  --priv-path secrets/fed-es256-private.jwk \
  --out-path  data/www/.well-known/openid-federation
```

If defaults are used outside a container and files are missing, the script fails
fast and prints hints.

### Continuous run

Inside the container with defaults:

```bash
python signer.py
```

Example log:

```
[signer] start. interval=3600s
[signer] cycle=1 signing at 2025-09-25T14:36:03+0000
[signer] done in 12ms exp=1758880000 next=2025-09-25T15:36:03+0000
```


## Key generator (`tools/ess_keygen.py`)

Generates an EC private JWK, a public JWK, and a JWKS for use by `oidf-ess`.
Defaults to ES256 (`P-256`). Does not overwrite existing files unless `--force`
is supplied.

### Usage

```bash
python tools/ess_keygen.py \
  --out-private secrets/fed-es256-private.jwk \
  --out-public  config/fed-es256-public.jwk \
  --out-jwks    config/fed-jwks.json
```

Options:

* `--curve {P-256,P-384,P-521}` (default `P-256`)
* `--kid <string>` (default `ess-YYYYMMDD-HHMMSS`)
* `--out-private <path>` private JWK (chmod 600)
* `--out-public <path>` public JWK (chmod 644)
* `--out-jwks <path>` JWKS with public key (chmod 644)
* `--force` overwrite existing files

### Behavior

* Creates parent directories if needed
* Prints a machine-readable JSON summary to stdout:

  ```json
  {
    "kid": "ess-20250925-143603",
    "curve": "P-256",
    "private_jwk": "/abs/path/secrets/fed-es256-private.jwk",
    "public_jwk": "/abs/path/config/fed-es256-public.jwk",
    "jwks": "/abs/path/config/fed-jwks.json",
    "created": 1758881763
  }
  ```
* Exits with:

  * `0` success
  * `1` nothing written (files exist, no `--force`)
  * `2` validation failure


## Security notes

* The private JWK is written with mode `600`. Do not commit `secrets/` to
  version control.
* The TLS private key is written with mode `600`. Use it for development,
  testing, or behind a reverse proxy that terminates external TLS.
* Running services as `${UID}:${GID}` ensures that bind-mounted files are
  created and remain readable by the calling user. In hardened environments,
  operators MUST implement sufficient measures for secure handling of ownership
  and permissions.

