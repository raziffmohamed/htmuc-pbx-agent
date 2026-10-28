"""Scheduler: fetch the scope from the UC, run the collectors on their own cadence, push changed or aging snapshots."""
import hashlib, json, sys, time

from . import __version__
from .collectors import COLLECTORS, valid_entries
from .pbx import AstDb, Pbx, PbxError, discover_families, parse_astdb, tenant_paths
from .protocol import Client, ProtocolError


def log(msg):
    print(msg, file=sys.stderr, flush=True)


class Agent:
    def __init__(self, cfg, client=None, pbx=None, clock=time.time):
        self.cfg, self.clock = cfg, clock
        self.pbx = pbx or Pbx(cfg)
        self.client = client or Client(cfg['uc_url'], cfg['agent_id'], cfg['secret'], ca_file=cfg.get('ca_file'),
                                       allow_http_localhost=cfg.get('allow_http_localhost', False), version=__version__)
        self.scope, self.scope_at = [], 0.0
        self.sent = {}          # kind -> (hash, time)
        self.due = {k: 0.0 for k in COLLECTORS}
        self.fail_streak = 0

    def refresh_scope(self):
        data = self.client.call('GET', 'scope')
        if not data.get('ok') or not isinstance(data.get('entries'), list):
            raise ProtocolError('scope reply malformed')
        entries = valid_entries(data['entries'])
        allowed = {str(x) for x in self.cfg.get('allowed_tenants') or []}
        if allowed:
            entries = [e for e in entries if e[1] in allowed]       # the agent's own limit wins over the UC's scope
        self.scope, self.scope_at = entries, self.clock()
        return len(self.scope)

    def families(self):
        """Config wins; tenants it does not name get their family from ombu_tenants.path (refreshed every 10 minutes)."""
        now = self.clock()
        if now - getattr(self, '_paths_at', -1e9) > 600:
            try:
                self._paths = tenant_paths(self.pbx)
            except (PbxError, ValueError):
                self._paths = getattr(self, '_paths', {})
            self._paths_at = now
        merged = dict(self._paths)
        merged.update(self.cfg.get('tenant_families') or {})
        return merged

    def collect(self, kind):
        return COLLECTORS[kind](self.pbx, self.scope, self.families())

    def push(self, kind, payload):
        body = {'agent_version': __version__, 'generated_unix': int(self.clock()), 'payload': payload}
        reply = self.client.call('POST', 'push', kind, body)
        if not reply.get('ok'):
            raise ProtocolError('push refused: %s' % str(reply.get('error', ''))[:80])

    def tick(self):
        """One pass. Returns the list of kinds pushed."""
        now = self.clock()
        pushed = []
        if now - self.scope_at >= self.cfg['scope_refresh_seconds']:
            try:
                n = self.refresh_scope()
                if n == 0:
                    log('scope is empty: no active UC users with an extension')
            except ProtocolError as e:
                log('scope fetch failed: %s' % e)
                if now - self.scope_at > self.cfg['scope_max_age_seconds']:
                    self.scope = []       # do not keep reporting for a scope the UC has not confirmed recently
                raise
        for kind in COLLECTORS:
            if now < self.due[kind]:
                continue
            self.due[kind] = now + self.cfg['intervals'][kind]
            try:
                payload = self.collect(kind)
            except PbxError as e:
                log('%s collection failed: %s' % (kind, e))
                continue
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            last = self.sent.get(kind)
            if last and last[0] == digest and now - last[1] < self.cfg['max_age'][kind]:
                continue
            self.push(kind, payload)
            self.sent[kind] = (digest, now)
            pushed.append(kind)
        return pushed

    def run_forever(self, sleep=time.sleep):
        log('htmuc-pbx-agent %s started; UC %s' % (__version__, self.cfg['uc_url']))
        while True:
            try:
                self.tick()
                self.fail_streak = 0
                sleep(1)
            except ProtocolError as e:
                self.fail_streak += 1
                delay = min(60, 2 ** min(self.fail_streak, 6))
                log('UC unreachable or refused (%s); retry in %ds' % (e, delay))
                sleep(delay)
            except Exception as e:      # never die on a collector bug: log and continue
                log('unexpected error: %s: %s' % (e.__class__.__name__, e))
                sleep(5)


def discover(cfg):
    """Report which Asterisk families look like tenant diversion trees, to help fill tenant_families."""
    pbx = Pbx(cfg)
    return discover_families(parse_astdb(pbx.ast('database show')))
