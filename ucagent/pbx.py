"""Read-only access to the local Asterisk and the PBX database. Fixed commands only; no caller-supplied strings reach a shell."""
import re, subprocess

_AST_ALLOWED = (
    re.compile(r'^core show hints$'),
    re.compile(r'^database show$'),
    re.compile(r'^database show CustomDevstate$'),
    re.compile(r'^database show [A-Za-z0-9_-]{1,100}$'),
)
MAX_OUTPUT = 16 * 1024 * 1024


class PbxError(Exception):
    pass


class Pbx:
    def __init__(self, cfg):
        self.asterisk_bin, self.mysql_bin, self.database = cfg['asterisk_bin'], cfg['mysql_bin'], cfg['mysql_database']

    def ast(self, command, timeout=15):
        if not any(p.match(command) for p in _AST_ALLOWED):
            raise PbxError('command not allowed: %r' % command[:60])
        try:
            p = subprocess.run([self.asterisk_bin, '-rx', command], capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise PbxError('asterisk failed: %s' % e.__class__.__name__)
        if p.returncode != 0:
            raise PbxError('asterisk returned %d' % p.returncode)
        return p.stdout[:MAX_OUTPUT]

    def sql(self, query, timeout=20):
        """Runs a SELECT as root over the local socket. The session is forced read-only first."""
        if not re.match(r'^\s*SELECT\b', query, re.I) or ';' in query:
            raise PbxError('only a single SELECT is allowed')
        try:
            p = subprocess.run([self.mysql_bin, '--protocol=socket', '--batch', '--skip-column-names', self.database, '-e',
                                'SET SESSION TRANSACTION READ ONLY; ' + query], capture_output=True, text=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise PbxError('mysql failed: %s' % e.__class__.__name__)
        if p.returncode != 0:
            raise PbxError('mysql returned %d' % p.returncode)
        return [line.split('\t') for line in p.stdout.splitlines()]


_HINT = re.compile(r'^\s*(\d{1,16})@((?:T(\d{1,8})_)?[\w-]+)\s*:(.*)$')


def parse_hints(text, default_tenant=None):
    """{(pbx_tenant, extension): [text after the colon, ...]}.
    Tenants other than the PBX default use contexts such as T9_extension-hints. The default tenant's hints sit in the
    plain `extension-hints` context, so they are attributed to `default_tenant` when it is known."""
    out = {}
    for line in text.splitlines():
        m = _HINT.match(line)
        if not m:
            continue
        tenant = m.group(3)
        if tenant is None:
            if default_tenant is None or m.group(2) != 'extension-hints':
                continue
            tenant = default_tenant
        out.setdefault((tenant, m.group(1)), []).append(m.group(4))
    return out


def default_tenant(pbx):
    """PBX tenant id flagged as the default tenant, or None."""
    try:
        rows = pbx.sql("SELECT tenant_id FROM ombu_tenants WHERE `default`='yes' LIMIT 1")
    except PbxError:
        return None
    return rows[0][0] if len(rows) == 1 and len(rows[0]) == 1 and re.fullmatch(r'\d{1,8}', rows[0][0]) else None


_DBLINE = re.compile(r'^(/[^\s:]*)\s*:\s*(.*?)\s*$')


def parse_astdb(text):
    """{'/family/key/path': 'value'} from `database show` output (lines look like '/Family/key        : value')."""
    out = {}
    for line in text.splitlines():
        m = _DBLINE.match(line)
        if m:
            out[m.group(1)] = m.group(2)
    return out


class AstDb:
    """A snapshot of the Asterisk database. get('T9_x/diversions/201/DND', 'enable') == the value of that key, or None."""
    def __init__(self, mapping):
        self.map = mapping

    def get(self, family, key):
        return self.map.get('/' + family.strip('/') + '/' + key)


class FamilyDb:
    """Lazy per-family view of the Asterisk database: runs `database show <family>` once per family instead of dumping everything."""
    def __init__(self, pbx):
        self.pbx, self.loaded = pbx, {}

    def get(self, family, key):
        top = family.strip('/').split('/')[0]
        if top not in self.loaded:
            self.loaded[top] = AstDb(parse_astdb(self.pbx.ast('database show ' + top)))
        return self.loaded[top].get(family, key)


_PATH = re.compile(r'^[A-Za-z0-9_-]{4,100}$')


def tenant_paths(pbx):
    """{pbx tenant id: Asterisk family} from ombu_tenants.path (VitalPBX names a tenant's Asterisk family after its path)."""
    out = {}
    for row in pbx.sql('SELECT tenant_id,IFNULL(path,\'\') FROM ombu_tenants'):
        if len(row) == 2 and re.fullmatch(r'\d{1,8}', row[0]) and _PATH.match(row[1]):
            out[row[0]] = row[1]
    return out


def discover_families(astdb_map):
    """Top-level families that contain a diversions tree, grouped by the tenant number in a T<number>_ name."""
    found = {}
    for path in astdb_map:
        parts = path.split('/')
        if len(parts) > 3 and parts[2] == 'diversions' and re.fullmatch(r'T(\d{1,8})_[A-Za-z0-9]+', parts[1]):
            found.setdefault(re.match(r'T(\d+)_', parts[1]).group(1), set()).add(parts[1])
    return {k: sorted(v) for k, v in found.items()}
