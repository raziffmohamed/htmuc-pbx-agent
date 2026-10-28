#!/usr/bin/env python3
"""Installs the HTM UC PBX agent on the PBX host (run as root).

  python3 install_agent.py --uc-url https://uc.example.com/uc/ --agent-id ag_... [--secret-file F] [--yes]
  python3 install_agent.py --uninstall

The secret is read from --secret-file, $UCAGENT_SECRET, or a hidden prompt; it is never put on a command line.
Nothing is changed on the PBX itself: the agent only reads Asterisk and the PBX database.
"""
import argparse, getpass, json, os, pathlib, re, shutil, subprocess, sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from ucagent import __version__                      # noqa: E402

APP = pathlib.Path('/opt/htmuc-agent')
CFG_DIR = pathlib.Path('/etc/htmuc-agent')
CFG = CFG_DIR / 'agent.json'
UNIT = pathlib.Path('/etc/systemd/system/htmuc-agent.service')


def die(msg):
    print('ERROR: ' + msg, file=sys.stderr)
    sys.exit(1)


def ask(prompt, default=None, yes=False):
    if yes and default is not None:
        return default
    s = input('%s%s: ' % (prompt, ' [%s]' % default if default else '')).strip()
    return s or default or ''


def discover(asterisk):
    """{pbx tenant id: [families]}. VitalPBX names a tenant's Asterisk family after ombu_tenants.path; fall back to T<id>_ names."""
    from ucagent.pbx import Pbx, PbxError, discover_families, parse_astdb, tenant_paths
    p = Pbx({'asterisk_bin': asterisk, 'mysql_bin': '/usr/bin/mysql', 'mysql_database': 'ombutel'})
    try:
        paths = tenant_paths(p)
        if paths:
            return {k: [v] for k, v in paths.items()}
    except PbxError:
        pass
    return discover_families(parse_astdb(p.ast('database show')))


def uninstall(args):
    run = lambda *c: subprocess.run(c, capture_output=True, text=True)
    run('systemctl', 'disable', '--now', 'htmuc-agent')
    for p in (UNIT,):
        if p.exists():
            p.unlink()
    run('systemctl', 'daemon-reload')
    if APP.exists():
        shutil.rmtree(APP)
    if args.purge and CFG_DIR.exists():
        shutil.rmtree(CFG_DIR)
        print('Removed the agent, its service and %s.' % CFG_DIR)
    else:
        print('Removed the agent and its service. %s was kept (it holds the secret); use --purge to remove it too.' % CFG_DIR)
    print('Remember to delete the agent in the UC under Settings > PBX Agent.')


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--uc-url')
    ap.add_argument('--agent-id')
    ap.add_argument('--secret-file')
    ap.add_argument('--ca-file', help='PEM file when the UC uses a private CA')
    ap.add_argument('--asterisk', default='/usr/sbin/asterisk')
    ap.add_argument('--tenant', action='append', default=[], metavar='PBXID=FAMILY', help='repeatable; default: detect')
    ap.add_argument('--allow-tenant', action='append', default=[], metavar='PBXID', help='limit the agent to these PBX tenants (recommended)')
    ap.add_argument('--allow-http-localhost', action='store_true', help=argparse.SUPPRESS)   # tests only
    ap.add_argument('--no-start', action='store_true')
    ap.add_argument('--yes', action='store_true', help='accept defaults, never prompt (needs all values given)')
    ap.add_argument('--uninstall', action='store_true')
    ap.add_argument('--purge', action='store_true')
    args = ap.parse_args()
    if os.geteuid() != 0:
        die('run as root')
    if args.uninstall:
        return uninstall(args)
    if sys.version_info < (3, 8):
        die('Python 3.8 or newer is required')
    if not shutil.which('systemctl'):
        die('systemd is required')
    if not os.access(args.asterisk, os.X_OK):
        die('%s not found; is this a PBX host?' % args.asterisk)

    url = (args.uc_url or ask('UC URL (for example https://uc.example.com/uc/)')).strip()
    if not re.fullmatch(r'https://[A-Za-z0-9.-]+(:\d{1,5})?/[A-Za-z0-9._/-]*', url) and not (args.allow_http_localhost and re.fullmatch(r'http://127\.0\.0\.1:\d{1,5}/[A-Za-z0-9._/-]*', url)):
        die('the UC URL must start with https:// and contain no credentials')
    aid = (args.agent_id or ask('Agent ID (ag_...)')).strip()
    if not re.fullmatch(r'ag_[0-9a-f]{8,32}', aid):
        die('agent id looks wrong (expected ag_ followed by 8-32 hex characters, got %r)' % aid)
    if args.secret_file:
        secret = pathlib.Path(args.secret_file).read_text().strip()
    else:
        secret = os.environ.get('UCAGENT_SECRET') or getpass.getpass('Agent secret (hidden): ').strip()
    secret = ''.join(secret.split())
    if not re.fullmatch(r'[0-9a-f]{64}', secret):
        die('the secret must be the 64 hex characters shown once in Settings > PBX Agent (received %d characters)' % len(secret))

    families = {}
    for t in args.tenant:
        k, _, v = t.partition('=')
        families[k] = v
    if not families:
        found = discover(args.asterisk)
        print('Detected tenant families:', json.dumps(found) if found else 'none')
        for tid, names in sorted(found.items()):
            if args.allow_tenant and tid not in args.allow_tenant:
                continue
            if len(names) == 1:
                families[tid] = names[0]
            else:
                families[tid] = ask('PBX tenant %s has several families %s; which one' % (tid, names), names[0], args.yes)
    if not families:
        die('no tenant families detected; pass --tenant PBXID=FAMILY')

    cfg = {'uc_url': url if url.endswith('/') else url + '/', 'agent_id': aid, 'secret': secret, 'tenant_families': families}
    if args.allow_tenant:
        cfg['allowed_tenants'] = args.allow_tenant
    if args.allow_http_localhost:
        cfg['allow_http_localhost'] = True
    if args.ca_file:
        cfg['ca_file'] = args.ca_file
    print('\nAbout to install:\n  UC        %s\n  agent id  %s\n  tenants   %s\n  limited to %s\n' % (cfg['uc_url'], aid, families, args.allow_tenant or 'whatever the UC scope lists'))
    if not args.yes and ask('Proceed? (yes/no)', 'no').lower() != 'yes':
        die('cancelled')

    # Program files: root-owned and not writable by anyone else.
    if APP.exists():
        shutil.rmtree(APP)
    APP.mkdir(parents=True, mode=0o755)
    shutil.copytree(HERE / 'ucagent', APP / 'ucagent', ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copy2(HERE / 'htmuc-agent', APP / 'htmuc-agent')
    for f in [APP, *APP.rglob('*')]:
        os.chown(f, 0, 0)
        os.chmod(f, 0o755 if f.is_dir() or f.name == 'htmuc-agent' else 0o644)
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(CFG_DIR, 0o700)
    if CFG.exists():
        shutil.copy2(CFG, CFG.with_suffix('.json.bak'))
    tmp = CFG.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, CFG)
    shutil.copy2(HERE / 'systemd/htmuc-agent.service', UNIT)
    os.chmod(UNIT, 0o644)
    run = lambda *c: subprocess.run(c, capture_output=True, text=True)
    run('systemctl', 'daemon-reload')

    chk = subprocess.run([sys.executable, '-I', str(APP / 'htmuc-agent'), '--config', str(CFG), 'check'], cwd='/', capture_output=True, text=True)
    print((chk.stdout + chk.stderr).strip())
    if chk.returncode != 0:
        print('\nThe agent is installed but could not reach the UC. The service was NOT started. Fix the message above, then:\n  systemctl enable --now htmuc-agent')
        return 1
    if not args.no_start:
        r = run('systemctl', 'enable', '--now', 'htmuc-agent')
        if r.returncode:
            die('systemctl: ' + r.stderr.strip())
        print('Service htmuc-agent started. Logs: journalctl -u htmuc-agent -f')
    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
