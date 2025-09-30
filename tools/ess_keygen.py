#!/usr/bin/env python3
"""
Entity Statement Signer key generator.

Generates an EC private JWK, public JWK, and JWKS for use by oidf-ess.
Defaults to ES256 (P-256). Overwrite only with --force.
"""
import argparse, json, os, sys, time, pathlib
from cryptojwt.jwk.ec import new_ec_key

CURVES = {"P-256", "P-384", "P-521"}

def parse_args():
    ap = argparse.ArgumentParser(prog="ess_keygen", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("--curve", choices=sorted(CURVES), default="P-256")
    ap.add_argument("--kid", default=f"ess-{time.strftime('%Y%m%d-%H%M%S')}")
    ap.add_argument("--out-private", required=True, help="Path to private JWK (JSON) to write")
    ap.add_argument("--out-public", required=True, help="Path to public JWK (JSON) to write")
    ap.add_argument("--out-jwks", required=True, help="Path to JWKS (JSON) to write")
    ap.add_argument("--force", action="store_true", help="Overwrite existing files")
    return ap.parse_args()

def write_json(path: pathlib.Path, obj, mode=0o644, force=False):
    if path.exists() and not force:
        print(f"[ess_keygen] Exists: {path} (use --force to overwrite)", file=sys.stderr)
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj))
    os.chmod(path, mode)
    print(f"[ess_keygen] Wrote: {path}")
    return True

def main():
    a = parse_args()
    print (f"[ess_keygen] Generating EC key pair with curve {a.curve} and kid {a.kid}")
    key = new_ec_key(crv=a.curve, kid=a.kid)
    prv = key.serialize(private=True)
    pub = key.serialize()
    jwks = {"keys": [pub]}

    # Sanity check
    if pub.get("crv") != a.curve or pub.get("kty") != "EC":
        print("[ess_keygen] Invalid public JWK generated", file=sys.stderr)
        sys.exit(2)

    ok1 = write_json(pathlib.Path(a.out_private), prv, mode=0o600, force=a.force)
    ok2 = write_json(pathlib.Path(a.out_public), pub, mode=0o644, force=a.force)
    ok3 = write_json(pathlib.Path(a.out_jwks), jwks, mode=0o644, force=a.force)

    # Machine-readable summary on stdout
    print(json.dumps({
        "kid": a.kid,
        "curve": a.curve,
        "private_jwk": str(pathlib.Path(a.out_private).resolve()),
        "public_jwk": str(pathlib.Path(a.out_public).resolve()),
        "jwks": str(pathlib.Path(a.out_jwks).resolve()),
        "created": int(time.time())
    }))
    # Exit nonzero if nothing was written and not forced
    if not any([ok1, ok2, ok3]) and not a.force:
        sys.exit(1)

if __name__ == "__main__":
    main()
