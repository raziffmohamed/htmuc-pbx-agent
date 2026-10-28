"""Collectors. Each returns exactly the JSON the UC's local collectors write, so the UC pages read it unchanged.

scope entries are (uc_tenant_id, pbx_tenant_id, extension); snapshot keys are "<uc_tenant_id>:<extension>".
"""
import re

from .pbx import FamilyDb, default_tenant, parse_hints

FAMILY = re.compile(r'^[A-Za-z0-9_-]{4,100}$')
EXT = re.compile(r'^\d{1,16}$')
PBX_ID = re.compile(r'^\d{1,8}$')


def valid_entries(scope):
    out = []
    for e in scope:
        try:
            uc, pbx, ext = int(e[0]), str(e[1]), str(e[2]).strip()
        except (TypeError, ValueError, IndexError):
            continue
        if uc > 0 and PBX_ID.match(pbx) and EXT.match(ext):
            out.append((uc, pbx, ext))
    return out


def _flag(v):
    return 'enabled' if v == 'yes' else 'disabled' if v == 'no' else 'unknown'


def hint_state(text):
    t = text.lower()
    if 'ringing' in t:
        return 'ringing'
    if 'unavailable' in t:
        return 'unavailable'      # no reachable device registered (legacy collectors reported this as unknown)
    if 'not_inuse' in t or 'not in use' in t or 'idle' in t:
        return 'idle'
    if 'inuse' in t or 'in use' in t or 'busy' in t:
        return 'busy'
    return 'unknown'


def collect_blf(pbx, scope, families, tenants=(), extensions=None):
    dt = default_tenant(pbx)
    hints = parse_hints(pbx.ast('core show hints'), dt)
    try:
        custom_text = pbx.ast('database show CustomDevstate')
    except Exception:
        custom_text = ''
    custom = {m.group(1): m.group(2).upper() for m in re.finditer(r'^/CustomDevstate/((?:T\d+_)?DND_\d+)\s*:\s*([A-Z_]+)', custom_text, re.M | re.I)}
    db = None
    states, mismatches = {}, {}
    for uc, p, ext in valid_entries(scope):
        found = hints.get((p, ext), [])
        if len(found) != 1:
            continue
        key = '%d:%s' % (uc, ext)
        states[key] = hint_state(found[0])
        family, c = families.get(p), custom.get('T%s_DND_%s' % (p, ext))
        if c is None and p == dt:
            c = custom.get('DND_%s' % ext)           # the default tenant's states carry no T<id>_ prefix
        if not family or not FAMILY.match(family) or c is None:
            continue
        if db is None:
            db = FamilyDb(pbx)
        v = db.get(family + '/diversions/' + ext + '/DND', 'enable')
        if v is None or v.lower() not in ('yes', 'no'):
            continue
        configured = v.lower()
        expected = 'INUSE' if configured == 'yes' else 'NOT_INUSE'
        if configured == 'no' and c in ('NOT_INUSE', 'UNAVAILABLE'):
            continue
        if c != expected:
            mismatches[key] = {'configured_dnd': configured, 'custom_device_state': c, 'expected_device_state': expected}
    # Every PBX extension of the visible tenants (known from the 'extensions' snapshot), even without a UC user:
    # report its hint state; one without a hint (no device assigned) is reported as unavailable.
    pbx_of = {uc: p for uc, p in (tenants or ())}
    for uc, exts in (extensions or {}).items():
        p = pbx_of.get(uc)
        if p is None:
            continue
        for ext in exts:
            key = '%d:%s' % (uc, ext)
            if key in states:
                continue
            found = hints.get((p, ext), [])
            states[key] = hint_state(found[0]) if len(found) == 1 else 'unavailable'
    return {'states': states, 'dnd_mismatches': mismatches}


def collect_routing(pbx, scope, families, tenants=(), extensions=None):
    db = FamilyDb(pbx)
    result = {}
    for uc, p, ext in valid_entries(scope):
        family = families.get(p)
        if not family or not FAMILY.match(family):
            continue
        fam = family + '/diversions/' + ext
        dnd = _flag(db.get(fam + '/DND', 'enable'))
        fwd = _flag(db.get(fam + '/CFI', 'enable'))
        dest = db.get(fam + '/CFI', 'destination')
        dest = dest if dest is not None and re.fullmatch(r'[0-9*#]{1,32}', dest) else ''
        result['%d:%s' % (uc, ext)] = {'dnd': dnd, 'forward_immediate': fwd,
                                        'forward_destination': dest if fwd == 'enabled' else '', 'forward_destination_saved': bool(dest)}
    return {'states': result}


def _clean(value, limit=80):
    return re.sub(r'[^\w .,&()/-]', '', value.replace('\\n', ' ').replace('\\t', ' '))[:limit].strip()


def collect_cos(pbx, scope, families, tenants=(), extensions=None):
    pairs = valid_entries(scope)
    result, status = {}, 'ok'
    if pairs:
        tenants = sorted({int(p) for _, p, _ in pairs})
        exts = sorted({e for _, _, e in pairs})
        query = ("SELECT e.tenant_id,e.extension,e.class_of_service_id,IFNULL(c.cos,''),IFNULL(c.description,''),IFNULL(c.ars_id,''),"
                 "IFNULL(c.dialrule_id,''),IFNULL(c.allowed_calls_by,''),IFNULL(c.private,'') "
                 "FROM ombu_extensions e LEFT JOIN ombu_classes_of_service c ON c.class_of_service_id=e.class_of_service_id "
                 "WHERE e.tenant_id IN (%s) AND e.extension IN (%s)" % (','.join(str(t) for t in tenants), ','.join("'%s'" % e for e in exts)))
        try:
            rows = pbx.sql(query)
        except Exception:
            rows, status = [], 'pbx_query_failed'
        found = {(r[0], r[1]): r for r in rows if len(r) == 9}
        if status == 'ok':
            for uc, p, ext in pairs:
                r = found.get((p, ext))
                if not r:
                    result['%d:%s' % (uc, ext)] = {'known': False}
                    continue
                ars, rule, calls_by = r[5] not in ('', 'NULL'), r[6] not in ('', 'NULL'), r[7] not in ('', 'NULL')
                result['%d:%s' % (uc, ext)] = {'known': True, 'cos_id': int(r[2]) if r[2].isdigit() else None, 'cos': _clean(r[3]), 'description': _clean(r[4]),
                                                'restricted': ars or rule or calls_by, 'outbound_route_set': ars, 'dial_rules': rule, 'allowed_calls_by': calls_by}
    return {'status': status, 'states': result}


MAX_EXTENSIONS = 3000


def valid_tenants(items):
    out = []
    for e in items or ():
        try:
            uc, pbx = int(e[0]), str(e[1])
        except (TypeError, ValueError, IndexError):
            continue
        if uc > 0 and PBX_ID.match(pbx):
            out.append((uc, pbx))
    return out


def collect_extensions(pbx, scope, families, tenants=(), extensions=None):
    """Every extension the PBX has in the visible tenants, with its display name: the UC lists them on Calls even when nobody uses the app."""
    pairs = valid_tenants(tenants)
    result, status = {}, 'ok'
    if pairs:
        ids = ','.join(sorted({p for _, p in pairs}, key=int))
        rows = None
        for cols in ("e.tenant_id,e.extension,IFNULL(e.name,'')", "e.tenant_id,e.extension,''"):
            try:
                rows = pbx.sql("SELECT %s FROM ombu_extensions e WHERE e.tenant_id IN (%s) ORDER BY e.tenant_id,e.extension LIMIT %d" % (cols, ids, MAX_EXTENSIONS))
                break
            except Exception:
                continue
        if rows is None:
            status = 'pbx_query_failed'
        else:
            by_tenant = {}
            for uc, p in pairs:
                by_tenant.setdefault(p, []).append(uc)
            for r in rows:
                if len(r) != 3 or not EXT.match(r[1]):
                    continue
                for uc in by_tenant.get(r[0], []):
                    result['%d:%s' % (uc, r[1])] = {'name': _clean(r[2])}
    return {'status': status, 'states': result}


COLLECTORS = {'extensions': collect_extensions, 'blf': collect_blf, 'routing': collect_routing, 'cos': collect_cos}
