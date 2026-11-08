"""CLI: python -m companion [-c config.yaml] serve|scan|pair|check-config"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys

from . import config as config_mod
from . import netfix


def build(cfg_path: str, notify: bool = True):
    from .collector import Collector, PinStore
    from .db import DB
    from .engine import Engine
    from .pairing import ensure_state

    cfg = config_mod.load(cfg_path)
    token, first = ensure_state(cfg)
    if cfg.tls:
        from .tls import ensure_cert
        ensure_cert(cfg.state_dir, cfg.bind_host)
    db = DB(cfg.state_dir / "tileops.db")
    engine = Engine(cfg, db, Collector(PinStore(cfg.state_dir / "known_hosts")), notify_enabled=notify)
    from .servers import ServerRegistry
    ServerRegistry(cfg, db, engine.collector.pins).load()
    return cfg, engine, token, first


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="tileops-companion")
    p.add_argument("-c", "--config", default=os.environ.get("TILEOPS_CONFIG", "config.yaml"))
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run API + scheduler")
    sc = sub.add_parser("scan", help="scan once and print results")
    sc.add_argument("server", nargs="?")
    sub.add_parser("pair", help="print pairing token + QR again")
    sub.add_parser("check-config")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("asyncssh").setLevel(logging.WARNING)  # per-channel INFO spam
    netfix.install()
    os.umask(0o077)

    if args.cmd == "check-config":
        cfg = config_mod.load(args.config)
        print(f"ok: {len(cfg.servers)} server(s), bind {cfg.bind_host}:{cfg.bind_port}")
        return 0

    cfg, engine, token, first = build(args.config)

    if args.cmd == "pair":
        from .pairing import print_pairing
        print_pairing(cfg, token)
        return 0

    if args.cmd == "scan":
        names = [args.server] if args.server else [s.name for s in cfg.servers]

        async def go():
            out = [await engine.scan(n) for n in names]
            await asyncio.sleep(0)
            return out

        print(json.dumps(asyncio.run(go()), indent=2, default=str))
        return 0

    if args.cmd == "serve":
        import uvicorn

        from .ai import enabled as ai_enabled
        from .api import create_app
        from .pairing import print_pairing

        if first:
            print_pairing(cfg, token)
        else:
            print(f"TileOps companion on {cfg.public_url} (run `python -m companion pair` to show the "
                  f"pairing QR again)", flush=True)
        print(f"AI investigator: {'enabled (' + cfg.ai_model + ')' if ai_enabled() else 'AI not configured'}",
              flush=True)
        app = create_app(engine, token)
        tls_args = {}
        if cfg.tls:
            tls_args = {"ssl_keyfile": str(cfg.state_dir / "tls.key"), "ssl_certfile": str(cfg.state_dir / "tls.crt")}
        uvicorn.run(app, host=cfg.bind_host, port=cfg.bind_port, log_level="info",
                    proxy_headers=False, server_header=False, **tls_args)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
