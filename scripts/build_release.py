#!/usr/bin/env python3
"""Builds dist/ucagent-<version>.tar.gz deterministically and prints its SHA-256."""
import gzip, hashlib, io, pathlib, sys, tarfile
root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from ucagent import __version__
names = [root / 'install_agent.py', root / 'htmuc-agent', root / 'systemd/htmuc-agent.service', root / 'README.md']
files = sorted([p for p in (root / 'ucagent').rglob('*.py')] + [n for n in names if n.exists()])
buf = io.BytesIO()
with tarfile.open(fileobj=buf, mode='w') as t:
    for p in files:
        data = p.read_bytes(); ti = tarfile.TarInfo('ucagent-%s/%s' % (__version__, p.relative_to(root).as_posix()))
        ti.size, ti.mtime, ti.mode, ti.uid, ti.gid, ti.uname, ti.gname = len(data), 0, 0o755 if p.name in ('install_agent.py', 'htmuc-agent') else 0o644, 0, 0, '', ''
        t.addfile(ti, io.BytesIO(data))
out = root / 'dist'; out.mkdir(exist_ok=True)
gz = io.BytesIO()
with gzip.GzipFile(fileobj=gz, mode='wb', mtime=0) as g:
    g.write(buf.getvalue())
(out / ('ucagent-%s.tar.gz' % __version__)).write_bytes(gz.getvalue())
print(hashlib.sha256(gz.getvalue()).hexdigest(), 'ucagent-%s.tar.gz' % __version__)
