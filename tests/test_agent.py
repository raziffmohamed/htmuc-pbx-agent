import json, os, pathlib, shutil, subprocess, sys, tempfile, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from ucagent import config, protocol
from ucagent.collectors import collect_blf, collect_cos, collect_routing, hint_state, valid_entries
from ucagent.daemon import Agent
from ucagent.pbx import Pbx, PbxError, discover_families, parse_astdb, parse_hints

HINTS = """-= Registered Asterisk Dial Plan Hints =-
100@T1_internal : PJSIP/T1_100&Custom:T1_DND_100 State:Idle Presence:not_set Watchers 1
101@T1_internal : PJSIP/T1_101 State:InUse Presence:not_set Watchers 1
100@T14_internal : PJSIP/T14_100 State:Ringing Watchers 1
102@T1_internal : PJSIP/T1_102 State:Idle Watchers 1
102@T1_other : PJSIP/T1_102 State:Idle Watchers 1
*65@default : Custom:x State:Idle
104@extension-hints : PJSIP/104&Custom:DND_104 State:Idle Watchers 1
701@other-hints : park State:Idle
"""
DB = """/T1_abc1/diversions/100/DND/enable : no
/T1_abc1/diversions/101/DND/enable : yes
/T1_abc1/diversions/101/CFI/enable : yes
/T1_abc1/diversions/101/CFI/destination : 8005551234
/T1_abc1/diversions/102/CFI/enable : yes
/T1_abc1/diversions/102/CFI/destination : evil;rm -rf
/T14_abc1/diversions/100/DND/enable : no
"""
CUSTOM = "/CustomDevstate/T1_DND_100 : INUSE\n/CustomDevstate/T1_DND_101 : NOT_INUSE\n/CustomDevstate/DND_104 : UNAVAILABLE\n"


class FakePbx:
    def __init__(self, sql_rows=None, fail_sql=False, default=False):
        self.rows, self.fail_sql, self.calls, self.default = sql_rows or [], fail_sql, [], default
    def ast(self, cmd, timeout=15):
        self.calls.append(cmd)
        if cmd.startswith('database show ') and cmd not in ('database show CustomDevstate',):
            fam = '/' + cmd.split(' ', 2)[2]
            return '\n'.join(l for l in DB.splitlines() if l.startswith(fam))
        return {'core show hints': HINTS, 'database show': DB, 'database show CustomDevstate': CUSTOM}[cmd]
    def sql(self, q, timeout=20):
        self.calls.append(q)
        if '`default`' in q:
            return [['1']] if self.default else []
        if 'ombu_tenants' in q:
            return [['1', 'T1_abc1'], ['14', 'T14_abc1'], ['bad', 'x']]
        if self.fail_sql:
            raise PbxError('x')
        return self.rows


FAM = {'1': 'T1_abc1', '14': 'T14_abc1'}
SCOPE = [(1, '1', '100'), (1, '1', '101'), (1, '1', '102'), (1, '1', '103'), (50, '14', '100')]


class Protocol(unittest.TestCase):
    def test_signature_matches_php(self):
        args = ('s' * 64, 'POST', 'push', 'blf', 1700000000, 'ab' * 12, 'cd' * 32)
        php = "echo hash_hmac('sha256', implode(\"\\n\", ['UCAGENT1','POST','push','blf','1700000000','%s','%s']), '%s');" % ('ab' * 12, 'cd' * 32, 's' * 64)
        out = subprocess.run(['php', '-r', php], capture_output=True, text=True).stdout
        self.assertEqual(protocol.request_sig(*args), out)
        php = "echo hash_hmac('sha256', implode(\"\\n\", ['UCAGENT1R','%s','%s']), '%s');" % ('ef' * 32, '12' * 32, 's' * 64)
        self.assertEqual(protocol.response_sig('s' * 64, 'ef' * 32, '12' * 32), subprocess.run(['php', '-r', php], capture_output=True, text=True).stdout)

    def test_https_required(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.Client('http://uc.example.test/uc/', 'ag_12345678', 'a' * 64)
        with self.assertRaises(protocol.ProtocolError):
            protocol.Client('http://example.test/uc/', 'ag_12345678', 'a' * 64, allow_http_localhost=True)
        protocol.Client('http://127.0.0.1:9/uc/', 'ag_12345678', 'a' * 64, allow_http_localhost=True)
        with self.assertRaises(protocol.ProtocolError):
            protocol.Client('https://u:p@uc.example.test/', 'ag_12345678', 'a' * 64)


class Parsers(unittest.TestCase):
    def test_hints(self):
        h = parse_hints(HINTS)
        self.assertEqual(sorted(h), [('1', '100'), ('1', '101'), ('1', '102'), ('14', '100')])
        self.assertEqual(len(h[('1', '102')]), 2)
        self.assertNotIn(('', '*65'), h)

    def test_hint_state(self):
        self.assertEqual([hint_state(x) for x in ('State:Idle', 'State:InUse', 'State:Ringing', 'State:NOT_INUSE', 'State:Unavailable')],
                         ['idle', 'busy', 'ringing', 'idle', 'unknown'])

    def test_astdb_and_discover(self):
        m = parse_astdb(DB)
        self.assertEqual(m['/T1_abc1/diversions/101/CFI/destination'], '8005551234')
        self.assertEqual(discover_families(m), {'1': ['T1_abc1'], '14': ['T14_abc1']})

    def test_allowlist(self):
        p = Pbx({'asterisk_bin': '/bin/true', 'mysql_bin': '/bin/true', 'mysql_database': 'x'})
        for bad in ('core restart now', 'database deltree T1_abc1', 'database show T1; x', 'originate Local/1 extension 2@x', 'database put a b c', 'dialplan reload'):
            with self.assertRaises(PbxError, msg=bad):
                p.ast(bad)
        for bad in ('DELETE FROM ombu_extensions', 'SELECT 1; DROP TABLE x', 'UPDATE x SET a=1'):
            with self.assertRaises(PbxError, msg=bad):
                p.sql(bad)

    def test_entries_validation(self):
        self.assertEqual(valid_entries([[1, '1', '100'], ['x', '1', '100'], [1, 'a', '100'], [1, '1', '1;2'], [1, '1'], [0, '1', '100'], None]), [(1, '1', '100')])


class Collectors(unittest.TestCase):
    def test_blf(self):
        out = collect_blf(FakePbx(), SCOPE, FAM)
        self.assertEqual(out['states'], {'1:100': 'idle', '1:101': 'busy', '50:100': 'ringing'})   # 102 ambiguous, 103 unknown: skipped
        self.assertEqual(out['dnd_mismatches']['1:100'], {'configured_dnd': 'no', 'custom_device_state': 'INUSE', 'expected_device_state': 'NOT_INUSE'})
        self.assertEqual(out['dnd_mismatches']['1:101']['expected_device_state'], 'INUSE')

    def test_blf_default_tenant_plain_context(self):
        scope = [(1, '1', '104')]
        self.assertEqual(collect_blf(FakePbx(default=True), scope, FAM)['states'], {'1:104': 'idle'})
        self.assertEqual(collect_blf(FakePbx(default=False), scope, FAM)['states'], {})      # without a known default tenant the plain context is ignored
        self.assertNotIn(('1', '701'), parse_hints(HINTS, '1'))                                # only the extension-hints context counts

    def test_routing(self):
        s = collect_routing(FakePbx(), SCOPE, FAM)['states']
        self.assertEqual(s['1:101'], {'dnd': 'enabled', 'forward_immediate': 'enabled', 'forward_destination': '8005551234', 'forward_destination_saved': True})
        self.assertEqual(s['1:102']['forward_destination'], '')
        self.assertEqual(s['50:100']['dnd'], 'disabled')
        self.assertEqual(s['1:103']['dnd'], 'unknown')

    def test_routing_ignores_unmapped_tenant(self):
        self.assertEqual(collect_routing(FakePbx(), [(1, '77', '100')], FAM)['states'], {})

    def test_cos(self):
        rows = [['1', '100', '1', 'all', 'All', 'NULL', 'NULL', 'NULL', 'no'], ['1', '101', '2', 'fd<b>', 'x', '5', 'NULL', 'NULL', 'no']]
        out = collect_cos(FakePbx(rows), SCOPE[:3], FAM)
        self.assertEqual(out['status'], 'ok')
        self.assertFalse(out['states']['1:100']['restricted'])
        self.assertTrue(out['states']['1:101']['restricted'])
        self.assertEqual(out['states']['1:101']['cos'], 'fdb')
        self.assertEqual(out['states']['1:102'], {'known': False})
        self.assertEqual(collect_cos(FakePbx(fail_sql=True), SCOPE, FAM), {'status': 'pbx_query_failed', 'states': {}})

    def test_cos_sql_is_a_single_select_with_numeric_values(self):
        p = FakePbx([])
        collect_cos(p, [(1, '1', '100'), (1, '1', "10'0")], FAM)          # the bad extension is dropped by validation
        q = p.calls[-1]
        self.assertTrue(q.startswith('SELECT')); self.assertNotIn("10'0", q); self.assertNotIn(';', q)


class Config(unittest.TestCase):
    def write(self, **over):
        d = tempfile.mkdtemp(); p = os.path.join(d, 'a.json')
        base = {'uc_url': 'https://uc.example.test/uc/', 'agent_id': 'ag_0123456789abcdef', 'secret': 'a' * 64, 'tenant_families': {'1': 'T1_abc1'}}
        base.update(over); open(p, 'w').write(json.dumps(base)); os.chmod(p, 0o600); return p

    def test_ok_and_defaults(self):
        c = config.load(self.write())
        self.assertEqual(c['intervals']['blf'], 5)
        self.assertEqual(c['allowed_tenants'], [])

    def test_rejects(self):
        for over in ({'secret': 'short'}, {'agent_id': 'x'}, {'tenant_families': {'a': 'T1_abc1'}}, {'tenant_families': {'1': 'bad name;'}},
                     {'intervals': {'blf': 0}}, {'allowed_tenants': ['x']}, {'uc_url': ''}):
            with self.assertRaises(config.ConfigError, msg=str(over)):
                config.load(self.write(**over))

    def test_permissions(self):
        p = self.write(); os.chmod(p, 0o644)
        with self.assertRaises(config.ConfigError):
            config.load(p)
        config.load(p, check_permissions=False)


class FakeClient:
    def __init__(self, entries):
        self.entries, self.pushed = entries, []
    def call(self, method, action, kind='', payload=None, now=None):
        if action == 'scope':
            return {'ok': True, 'entries': self.entries}
        self.pushed.append((kind, payload)); return {'ok': True}


class Daemon(unittest.TestCase):
    def mk(self, entries=None, **cfgover):
        cfg = config.load(Config().write(tenant_families=FAM, **cfgover))
        t = [1000.0]
        a = Agent(cfg, client=FakeClient(entries if entries is not None else [list(e) for e in SCOPE]), pbx=FakePbx([]), clock=lambda: t[0])
        return a, t

    def test_change_driven_and_heartbeat(self):
        a, t = self.mk()
        self.assertEqual(sorted(a.tick()), ['blf', 'cos', 'routing'])
        t[0] += 6; self.assertEqual(a.tick(), [])                      # unchanged and young: nothing sent
        t[0] += 20; self.assertEqual(sorted(a.tick()), ['blf', 'routing'])   # past their 20 s max_age: heartbeat; cos waits for 120 s

    def test_allowed_tenants_limit(self):
        a, t = self.mk(allowed_tenants=['14'])
        a.tick()
        for kind, body in a.client.pushed:
            self.assertTrue(all(k.startswith('50:') for k in body['payload']['states']), kind)

    def test_families_from_ombu_tenants_with_config_override(self):
        a, t = self.mk()
        a.cfg['tenant_families'] = {'14': 'OVERRIDE1'}
        self.assertEqual(a.families(), {'1': 'T1_abc1', '14': 'OVERRIDE1'})

    def test_empty_scope_pushes_empty(self):
        a, t = self.mk(entries=[])
        a.tick()
        self.assertEqual(a.client.pushed[0][1]['payload']['states'], {})

    def test_run_forever_survives_errors_and_backs_off(self):
        from ucagent.protocol import ProtocolError
        a, t = self.mk()
        calls = {'n': 0}
        def boom(*args, **kw):
            calls['n'] += 1
            raise ProtocolError('down')
        a.client.call = boom
        delays = []
        class Stop(Exception):
            pass
        def sleep(x):
            delays.append(x)
            if len(delays) >= 5:
                raise Stop()
        with self.assertRaises(Stop):
            a.run_forever(sleep=sleep)
        self.assertEqual(delays, [2, 4, 8, 16, 32])


if __name__ == '__main__':
    unittest.main()
