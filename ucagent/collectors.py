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


def collect_blf(pbx, scope, families):
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
    return {'states': states, 'dnd_mismatches': mismatches}


def collect_routing(pbx, scope, families):
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


def collect_cos(pbx, scope, families):
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


COLLECTORS = {'blf': collect_blf, 'routing': collect_routing, 'cos': collect_cos}
