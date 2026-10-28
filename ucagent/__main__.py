import argparse, json, os, re, sys

from . import __version__
from .config import DEFAULT_PATH, ConfigError, load
from .daemon import Agent, discover, log
from .pbx import Pbx, PbxError, discover_families, parse_astdb, parse_hints, tenant_paths
from .protocol import ProtocolError


def run_offline(command, cfg):
    try:
        if command == 'discover':
            print(json.dumps(discover(cfg), indent=2))
        else:
            print(sample(cfg))
    except PbxError as e:
        print('FAILED: %s' % e, file=sys.stderr)
        return 1
    return 0


def sample(cfg):
    """Redacted excerpts of what the collectors parse, to confirm formats on a real PBX. No secrets are read."""
    pbx = Pbx(cfg)
    hints = [l for l in pbx.ast('core show hints').splitlines() if re.search(r'@T\d+_', l)][:20]
    db = pbx.ast('database show').splitlines()
    try:
        rows = pbx.sql('SELECT tenant_id,name,IFNULL(path,\'\'),IFNULL(prefix,\'\') FROM ombu_tenants LIMIT 100')
    except PbxError as e:
        rows = [['sql failed: %s' % e]]
    div = [re.sub(r'(destination\s*:\s*)\S+', r'\1<masked>', l) for l in db if '/diversions/' in l][:30]
    custom = pbx.ast('database show CustomDevstate').splitlines()[:10]
    families = discover_families(parse_astdb('\n'.join(db)))
    parsed = parse_hints('\n'.join(hints))
    return '\n'.join(['== hints (first 20 tenant lines) ==', *hints, '== parsed hint keys ==', repr(sorted(parsed)[:20]),
                      '== astdb diversions (first 30, destinations masked) ==', *div, '== CustomDevstate (first 10) ==', *custom, '== ombu_tenants (id, name, path, device prefix) ==', *['\t'.join(r) for r in rows],
                      '== discovered families ==', json.dumps(families, indent=2)])


def main(argv=None):
    ap = argparse.ArgumentParser(prog='ucagent', description='HTM UC PBX agent')
    ap.add_argument('command', choices=['run', 'once', 'dry-run', 'discover', 'sample', 'check', 'version'])
    ap.add_argument('--config', default=DEFAULT_PATH)
    ap.add_argument('--no-permission-check', action='store_true', help='tests only')
    a = ap.parse_args(argv)
    if a.command == 'version':
        print(__version__)
        return 0
    if a.command in ('discover', 'sample') and not os.path.exists(a.config):
        from .config import DEFAULTS
        cfg = dict(DEFAULTS)        # read-only look at the PBX before the agent is configured
        return run_offline(a.command, cfg)
    try:
        cfg = load(a.config, check_permissions=not a.no_permission_check)
    except ConfigError as e:
        print('config error: %s' % e, file=sys.stderr)
        return 2
    if a.command in ('discover', 'sample'):
        return run_offline(a.command, cfg)
    agent = Agent(cfg)
    if a.command == 'check':
        try:
            n = agent.refresh_scope()
        except ProtocolError as e:
            print('FAILED: %s' % e)
            return 1
        print('OK: reached the UC, signature verified, scope has %d extensions' % n)
        return 0
    try:
        if a.command == 'dry-run':
            agent.refresh_scope()
            for kind in agent.due:
                print('== %s' % kind)
                print(json.dumps(agent.collect(kind), indent=2, sort_keys=True)[:4000])
            return 0
        if a.command == 'once':
            agent.refresh_scope()
            pushed = agent.tick()
            print('pushed: ' + (', '.join(pushed) if pushed else 'nothing'))
            return 0
        agent.run_forever()
    except (ProtocolError, PbxError) as e:
        print('FAILED: %s' % e, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == '__main__':
    sys.exit(main())
