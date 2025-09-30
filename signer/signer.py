import os, json, time, pathlib, sys
from cryptojwt.jws.jws import JWS
from cryptojwt.jwk.jwk import import_jwk
from urllib.parse import urlparse
import argparse


def _hint_local_path(p: pathlib.Path) -> str:
    # suggest a local repo path that mirrors your compose mounts
    mapping = {
        "/config/fed-jwks.json": "config/fed-jwks.json",
        "/config/entity-metadata.json": "config/entity-metadata.json",
        "/out/.well-known/openid-federation": "data/www/.well-known/openid-federation",
        "/run/secrets/fed-es256-private.jwk": "secrets/fed-es256-private.jwk",
    }
    return mapping.get(p.as_posix(), p.as_posix())


def preflight(args) -> None:
    problems = []

    if not args.jwks_path.exists():
        problems.append(f"- JWKS not found: {args.jwks_path}  (try: {_hint_local_path(args.jwks_path)})")
    if not args.meta_path.exists():
        problems.append(f"- metadata not found: {args.meta_path}  (try: {_hint_local_path(args.meta_path)})")
    if not args.priv_path.exists():
        problems.append(f"- private JWK not found: {args.priv_path}  (try: {_hint_local_path(args.priv_path)})")
    out_dir = args.out_path.parent
    if not out_dir.exists():
        problems.append(f"- publish directory missing: {out_dir}  (try: {_hint_local_path(out_dir)})")

    if problems:
        sys.stderr.write(
            "[signer] configuration error\n"
            "The default paths are intended for container execution.\n"
            "For a local one-time run, set explicit paths or run the bootstrap first.\n\n"
            "Missing or invalid paths:\n" + "\n".join(problems) + "\n\n"
            "Examples:\n"
            "  python signer.py --once \\\n"
            "    --entity-id https://entity.example.org \\\n"
            "    --jwks-path config/fed-jwks.json \\\n"
            "    --meta-path config/entity-metadata.json \\\n"
            "    --priv-path secrets/fed-es256-private.jwk \\\n"
            "    --out-path  data/www/.well-known/openid-federation\n\n"
            "Or run: ./bootstrap-oidf-ess.sh\n"
        )
        sys.exit(2)

def _env(name: str, default=None):
    return os.environ.get(name, default)


def _as_bool(v, default=False):
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _positive_int(text):
    try:
        val = int(text)
        if val <= 0:
            raise ValueError
        return val
    except ValueError:
        raise argparse.ArgumentTypeError(f"must be a positive integer (got {text!r})")
    

def _must_https(url: str) -> str:
    u = urlparse(url)
    if u.scheme != "https" or not u.netloc:
        raise argparse.ArgumentTypeError("ENTITY_ID must be an https URL")
    return url
    

def parse_config(argv=None):
    p = argparse.ArgumentParser(description="oidf-ess signer")
    ent_env = _env("ENTITY_ID")
    # Treat empty string as “not provided”
    is_missing = ent_env is None or ent_env.strip() == ""
    p.add_argument("--entity-id",
                   default=ent_env,
                   required=is_missing,
                   help="Federation entity identifier (ENV: ENTITY_ID)")
    p.add_argument("--resign-interval",
                   type=_positive_int,
                   default=int(_env("RESIGN_INTERVAL", "3600")),
                   help="Re-sign interval in seconds (ENV: RESIGN_INTERVAL, default 3600)")
    p.add_argument("--jwks-path",
                   type=pathlib.Path,
                   default=pathlib.Path(_env("JWKS_PATH", "/config/fed-jwks.json")),
                   help="Path to public JWKS (ENV: JWKS_PATH)")
    p.add_argument("--meta-path",
                   type=pathlib.Path,
                   default=pathlib.Path(_env("META_PATH", "/config/entity-metadata.json")),
                   help="Path to operator-maintained metadata (ENV: META_PATH)")
    p.add_argument("--out-path",
                   type=pathlib.Path,
                   default=pathlib.Path(_env("OUTPUT_PATH", "/out/.well-known/openid-federation")),
                   help="Publish target for compact Entity Statement (ENV: OUTPUT_PATH)")
    p.add_argument("--exp-seconds",
                   type=_positive_int,
                   default=int(_env("EXP_SECONDS", "86400")),
                   help="Entity Statement lifetime in seconds (ENV: EXP_SECONDS, default 86400)")
    p.add_argument("--priv-path",
                   type=pathlib.Path,
                   default=pathlib.Path(_env("PRIV_PATH", "/run/secrets/fed-es256-private.jwk")),
                   help="Private JWK path for ES256 signing (ENV: PRIV_PATH)")
    # one-time shoot
    p.add_argument("--once",
                   #dest="sign_once",
                   action="store_true",
                   default=_as_bool(_env("SIGNER_ONCE")),
                   help="Sign once and exit 0 (ENV: SIGNER_ONCE=1)")
    return p.parse_args(argv)

    # # Normalize to your existing variable names
    # return {
    #     "ENTITY_ID": args.entity_id,
    #     "RESIGN_INTERVAL": args.resign_interval,
    #     "JWKS_PATH": args.jwks_path,
    #     "META_PATH": args.meta_path,
    #     "OUT_PATH": args.out_path,
    #     "EXP_SECONDS": args.exp_seconds,
    #     "PRIV_PATH": args.priv_path,
    #     "SIGNER_ONCE": args.signer_once,
    # }



# args.entity_id   = os.environ["ENTITY_ID"]
# args.resign_interval = int(os.environ.get("RESIGN_INTERVAL", "3600"))
# args.jwks_path   = pathlib.Path(os.environ.get("JWKS_PATH", "/config/fed-jwks.json"))
# args.meta_path   = pathlib.Path(os.environ.get("META_PATH", "/config/entity-metadata.json"))
# args.out_path    = pathlib.Path(os.environ.get("OUTPUT_PATH", "/out/.well-known/openid-federation"))
# args.exp_seconds = int(os.environ.get("EXP_SECONDS", "86400"))
# args.priv_path   = pathlib.Path("/run/secrets/fed-es256-private.jwk")
# args.signer_once = pathlib.Path("/run/secrets/fed-es256-private.jwk")


def load_metadata(args):
    try:
        return json.loads(args.meta_path.read_text())
    except Exception as e:
        raise RuntimeError(f"Failed to parse metadata file: {e}")



def sign(args):
    #metadata = load_metadata(args)
    now = int(time.time())
    claims = {
        "iss": args.entity_id,
        "sub": args.entity_id,
        "iat": now,
        "exp": now + args.exp_seconds,
        "jwks": json.loads(args.jwks_path.read_text()),
    }
    claims.update(load_metadata(args))
    
    prv = import_jwk(args.priv_path)
    jws = JWS(claims, alg="ES256")
    token = jws.sign_compact([prv], protected={"typ": "entity-statement+jwt"})
    args.out_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.out_path.with_suffix(".tmp")
    tmp.write_text(token)
    tmp.replace(args.out_path)
    return claims["exp"]


def ts(t=None):
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(time.time() if t is None else t))


def main():
    args = parse_config()
    preflight(args)
    print(f"[signer] start. interval={args.resign_interval}s", flush=True)
    cycle = 0
    next_deadline = time.monotonic()  # start immediately

    if args.once:
        wall_start = time.time()
        mono_start = time.monotonic()
        print(f"[signer] cycle=1 signing at {ts(wall_start)}", flush=True)
        exp = sign(args)  # may return exp as epoch seconds
        dur_ms = int((time.monotonic() - mono_start) * 1000)
        msg = f"[signer] done in {dur_ms}ms"
        if isinstance(exp, int):
            msg += f" exp={exp}"
        print(msg + " (once)", flush=True)
        return 0  # exit immediately

    while True:
        now_mono = time.monotonic()
        if now_mono < next_deadline:
            remaining = next_deadline - now_mono  # float seconds
            print(f"[signer] sleeping {remaining:.3f}s (next={ts(time.time()+remaining)})", flush=True)
            time.sleep(remaining)
            continue

        cycle += 1
        wall_start = time.time()
        mono_start = time.monotonic()
        print(f"[signer] cycle={cycle} signing at {ts(wall_start)}", flush=True)
        exp = sign(args)  # optional: return exp as epoch seconds
        dur_ms = int((time.monotonic() - mono_start) * 1000)
        msg = f"[signer] done in {dur_ms}ms"
        if isinstance(exp, int):
            msg += f" exp={exp}"
        next_deadline += args.resign_interval
        if next_deadline < time.monotonic():
            next_deadline = time.monotonic()
        msg += f" next={ts(time.time() + max(0.0, next_deadline - time.monotonic()))}"
        print(msg, flush=True)

if __name__ == "__main__":
    main()
