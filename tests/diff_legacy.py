"""Differential test: the agent's collectors must produce the same snapshots as the UC's own local collectors.
Needs the UC package: UC_PKG=/path/to/VitalPBX-UC-... python3 tests/diff_legacy.py   (skipped otherwise)."""
import json, os, pathlib, re, sqlite3, subprocess, sys, tempfile, unittest
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from ucagent.collectors import COLLECTORS
from ucagent.pbx import Pbx

PKG = os.environ.get('UC_PKG')

FAKE_AST = r'''#!/bin/sh
case "$2" in
"core show hints") cat <<'H'
100@T1_internal      : PJSIP/T1_100&Custom:T1_DND_100 State:Idle         Presence:not_set        Watchers  1
101@T1_internal      : PJSIP/T1_101&Custom:T1_DND_101 State:InUse        Presence:not_set        Watchers  1
102@T1_internal      : PJSIP/T1_102 State:Ringing
103@T1_internal      : PJSIP/T1_103 State:Idle
103@T1_other         : PJSIP/T1_103 State:Idle
100@T14_internal     : PJSIP/T14_100                  State:Ringing      Presence:not_set        Watchers  1
110@T14_internal     : PJSIP/T14_110&Custom:T14_DND_110 State:Idle
H
;;
"database show CustomDevstate") cat <<'H'
/CustomDevstate/T1_DND_100                        : INUSE
/CustomDevstate/T1_DND_101                        : NOT_INUSE
/CustomDevstate/T14_DND_110                       : UNAVAILABLE
H
;;
"database show") cat <<'H'
/T1_abc1/diversions/100/DND/enable                : no
/T1_abc1/diversions/101/DND/enable                : yes
/T1_abc1/diversions/101/CFI/enable                : yes
/T1_abc1/diversions/101/CFI/destination           : 8005551234
/T1_abc1/diversions/102/CFI/enable                : yes
/T1_abc1/diversions/102/CFI/destination           : 7x
/T14_abc1/diversions/110/DND/enable               : no
/T14_abc1/diversions/110/CFI/enable               : no
H
;;
"database show T1_abc1") cat <<'H'
/T1_abc1/diversions/100/DND/enable                : no
/T1_abc1/diversions/101/DND/enable                : yes
/T1_abc1/diversions/101/CFI/enable                : yes
/T1_abc1/diversions/101/CFI/destination           : 8005551234
/T1_abc1/diversions/102/CFI/enable                : yes
/T1_abc1/diversions/102/CFI/destination           : 7x
H
;;
"database show T14_abc1") cat <<'H'
/T14_abc1/diversions/110/DND/enable               : no
/T14_abc1/diversions/110/CFI/enable               : no
H
;;
"database get T1_abc1/diversions/100/DND enable") echo "Value: no";;
"database get T1_abc1/diversions/101/DND enable") echo "Value: yes";;
"database get T1_abc1/diversions/101/CFI enable") echo "Value: yes";;
"database get T1_abc1/diversions/101/CFI destination") echo "Value: 8005551234";;
"database get T1_abc1/diversions/102/CFI enable") echo "Value: yes";;
"database get T1_abc1/diversions/102/CFI destination") echo "Value: 7x";;
"database get T14_abc1/diversions/110/DND enable") echo "Value: no";;
"database get T14_abc1/diversions/110/CFI enable") echo "Value: no";;
database\ get*) echo "Database entry not found."; exit 1;;
*) exit 1;;
esac
'''
FAKE_MYSQL = '''#!/bin/sh
printf '1\\t100\\t1\\tall\\tAll\\tNULL\\tNULL\\tNULL\\tno\\n'
printf '1\\t101\\t2\\tfd\\tFront\\t5\\tNULL\\tNULL\\tno\\n'
printf '14\\t110\\t4\\tx\\ty\\tNULL\\t3\\tNULL\\tno\\n'
'''


@unittest.skipUnless(PKG and os.geteuid() == 0, 'set UC_PKG and run as root')
class Diff(unittest.TestCase):
    def test_same_output(self):
        d = pathlib.Path(tempfile.mkdtemp()); (d / 'data').mkdir()
        ast, my = d / 'asterisk', d / 'mysql'
        ast.write_text(FAKE_AST); my.write_text(FAKE_MYSQL); ast.chmod(0o755); my.chmod(0o755)
        (d / 'data/uc-pbx-tenant-map.json').write_text(json.dumps({'1': 'T1_abc1', '14': 'T14_abc1'}))
        con = sqlite3.connect(d / 'data/uc.sqlite')
        con.executescript('CREATE TABLE users(id INTEGER PRIMARY KEY,extension TEXT,active INTEGER);CREATE TABLE tenants(id INTEGER PRIMARY KEY,pbx_tenant_id TEXT);CREATE TABLE user_tenants(user_id INT,tenant_id INT);')
        con.execute("INSERT INTO tenants VALUES(1,'1'),(50,'14')")
        users = [(1, '100', 1), (2, '101', 1), (3, '102', 1), (4, '103', 1), (5, '110', 1), (6, '999', 1), (7, '100', 1), (8, '555', 0)]
        for uid, ext, act in users:
            con.execute('INSERT INTO users VALUES(?,?,?)', (uid, ext, act))
        links = [(1, 1), (2, 1), (3, 1), (4, 1), (5, 50), (6, 1), (7, 50), (8, 1), (1, 50)]
        con.executemany('INSERT INTO user_tenants VALUES(?,?)', links); con.commit()
        scope = [list(r) for r in con.execute("SELECT DISTINCT t.id,t.pbx_tenant_id,u.extension FROM tenants t JOIN user_tenants ut ON ut.tenant_id=t.id JOIN users u ON u.id=ut.user_id WHERE u.active=1 AND u.extension IS NOT NULL AND u.extension!=''")]
        con.close()
        legacy = {}
        for script, out in (('uc-blf-collect.py', 'blf.json'), ('uc-pbx-routing-collect.py', 'pbx-routing.json'), ('uc-pbx-cos-collect.py', 'pbx-cos.json')):
            src = (pathlib.Path(PKG) / 'app/bin' / script).read_text()
            src = src.replace("/usr/share/vitalpbx/htmuc-uc'", str(d) + "'").replace("'/usr/sbin/asterisk'", repr(str(ast))).replace("MYSQL = '/usr/bin/mysql'", 'MYSQL = %r' % str(my))
            src = re.sub(r"os\.chown\(tmp,0,grp\.getgrnam\('www-data'\)\.gr_gid\);", '', src)
            src = re.sub(r"os\.chown\(tmp, 0, grp\.getgrnam\('www-data'\)\.gr_gid\);\s*", '', src)
            (d / script).write_text(src)
            r = subprocess.run([sys.executable, '-I', str(d / script)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, script + r.stderr[-400:])
            legacy[script] = json.loads((d / 'diagnostics' / out).read_text())
        pbx = Pbx({'asterisk_bin': str(ast), 'mysql_bin': str(my), 'mysql_database': 'ombutel'})
        fam = {'1': 'T1_abc1', '14': 'T14_abc1'}
        mine = {k: f(pbx, scope, fam) for k, f in COLLECTORS.items()}
        for key, script in (('blf', 'uc-blf-collect.py'), ('routing', 'uc-pbx-routing-collect.py'), ('cos', 'uc-pbx-cos-collect.py')):
            leg = {k: v for k, v in legacy[script].items() if k != 'generated_unix'}
            self.assertEqual(json.loads(json.dumps(mine[key])), leg, key)


if __name__ == '__main__':
    unittest.main()
