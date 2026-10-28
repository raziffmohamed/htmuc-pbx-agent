"""Agent configuration: /etc/htmuc-agent/agent.json (root-owned, mode 0600)."""
import json, os, re, stat

DEFAULT_PATH = '/etc/htmuc-agent/agent.json'
KINDS = ('extensions', 'blf', 'routing', 'cos')           # prefixes is added once its source query is verified on a real PBX
DEFAULTS = {
    'asterisk_bin': '/usr/sbin/asterisk',
    'mysql_bin': '/usr/bin/mysql',
    'mysql_database': 'ombutel',
    'tenant_families': {},
    'ca_file': None,
    'scope_refresh_seconds': 30,
    'scope_max_age_seconds': 300,
    'intervals': {'extensions': 60, 'blf': 5, 'routing': 10, 'cos': 60},
    'max_age': {'extensions': 600, 'blf': 20, 'routing': 20, 'cos': 120},
    'allow_http_localhost': False,
    'allowed_tenants': [],          # PBX tenant ids this agent may report on; empty = whatever the UC scope lists
}


class ConfigError(Exception):
    pass


def load(path=DEFAULT_PATH, check_permissions=True):
    try:
        st = os.lstat(path)
    except OSError as e:
        raise ConfigError('cannot read %s: %s' % (path, e.strerror))
    if not stat.S_ISREG(st.st_mode):
        raise ConfigError('%s must be a regular file' % path)
    if check_permissions:
        if st.st_mode & 0o077:
            raise ConfigError('%s must not be readable by group or others (chmod 600)' % path)
        if os.geteuid() == 0 and st.st_uid != 0:
            raise ConfigError('%s must be owned by root' % path)
    try:
        raw = json.loads(open(path).read())
    except ValueError as e:
        raise ConfigError('invalid JSON: %s' % e)
    if not isinstance(raw, dict):
        raise ConfigError('config must be an object')
    cfg = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULTS.items()}
    for key in ('intervals', 'max_age'):
        cfg[key].update(raw.get(key, {}) if isinstance(raw.get(key, {}), dict) else {})
    for key, value in raw.items():
        if key not in ('intervals', 'max_age'):
            cfg[key] = value
    if not isinstance(cfg.get('uc_url'), str) or not cfg['uc_url']:
        raise ConfigError('uc_url is required')
    if not re.fullmatch(r'ag_[0-9a-f]{8,32}', str(cfg.get('agent_id', ''))):
        raise ConfigError('agent_id is missing or malformed')
    if not re.fullmatch(r'[0-9a-f]{64}', str(cfg.get('secret', ''))):
        raise ConfigError('secret must be 64 hex characters')
    fam = cfg['tenant_families']
    if not isinstance(fam, dict) or any(not re.fullmatch(r'\d{1,8}', str(k)) or not re.fullmatch(r'[A-Za-z0-9_-]{4,100}', str(v)) for k, v in fam.items()):
        raise ConfigError('tenant_families must map numeric PBX tenant ids to Asterisk family names')
    at = cfg['allowed_tenants']
    if not isinstance(at, list) or any(not re.fullmatch(r'\d{1,8}', str(x)) for x in at):
        raise ConfigError('allowed_tenants must be a list of numeric PBX tenant ids')
    for key in KINDS:
        for table in ('intervals', 'max_age'):
            v = cfg[table].get(key)
            if not isinstance(v, int) or isinstance(v, bool) or not 1 <= v <= 3600:
                raise ConfigError('%s.%s must be 1-3600 seconds' % (table, key))
    return cfg
