#!/usr/bin/env python3
"""GDELT Events 2.0: protest, coercion, assault, fighting and mass-violence events → data/events.json.

Upstream: the 15-minute event export files (https://data.gdeltproject.org/gdeltv2/<stamp>.export.CSV.zip, 61 tab-separated
columns, no header; `lastupdate.txt` names the newest). Each run reads the files of the last ~75 minutes that it has not
read before (`files_seen` in the envelope, restored from the branch), keeps a rolling 48-hour window, and collapses the
rows by (CAMEO base code, 0.1° position, day) so one street protest reported by forty outlets is one record with forty
mentions — the shape the maps and briefs read. GDELT is free for any commercial use with citation and a link; DATA-
SOURCES.md §2.4. Coordinates are GDELT's city / ADM1 / country centroids, labelled admin1 or country, never "point".
"""
import io
import re
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from tf import get, write_if_changed, envelope, now, iso, log, fail, clip, read_json, data_path, FeedError
import events
import geocode

BASE = 'https://data.gdeltproject.org/gdeltv2/'
CREDIT = 'GDELT Project, Events 2.0 (https://www.gdeltproject.org/)'
LICENCE = 'GDELT: free for any use including commercial, with citation and a link to gdeltproject.org'
NOTICE = ('GDELT events are machine-coded from news reports, geolocated to a city, region or country centroid and never '
          'verified; mentions count reports, not people. A single row is signal, a cluster with many sources is a story.')
WINDOW_HOURS = 48
STEP_MIN = 15
LOOKBACK_FILES = 5          # the files of the last ~75 min: an hourly tick never misses one
MAX_ROWS = 6000
MIN_GOLDSTEIN_VIOLENCE = -5.0

# CAMEO base codes → (kind, threat_class, severity). Root 14 protest, 17 coerce, 18 assault, 19 fight, 20 mass violence.
CODES = {
    '140': ('protest', 'unrest', events.MINOR), '141': ('protest', 'unrest', events.MINOR), '142': ('hungerStrike', 'unrest', events.MINOR),
    '143': ('strike', 'unrest', events.MINOR), '144': ('blockade', 'unrest', events.MODERATE), '145': ('riot', 'unrest', events.MODERATE),
    '170': ('crackdown', 'unrest', events.MODERATE), '171': ('crackdown', 'unrest', events.MODERATE), '172': ('curfew', 'unrest', events.MODERATE),
    '173': ('massArrest', 'unrest', events.MODERATE), '174': ('expulsion', 'unrest', events.MODERATE), '175': ('repression', 'unrest', events.SEVERE),
    '180': ('assault', 'conflict', events.MODERATE), '181': ('abduction', 'conflict', events.MODERATE), '182': ('assault', 'conflict', events.MODERATE),
    '183': ('bombing', 'conflict', events.SEVERE), '184': ('assault', 'conflict', events.MODERATE), '185': ('assassination', 'conflict', events.SEVERE),
    '186': ('assassination', 'conflict', events.SEVERE),
    '190': ('armedClash', 'conflict', events.SEVERE), '191': ('blockade', 'conflict', events.MODERATE), '192': ('armedClash', 'conflict', events.SEVERE),
    '193': ('armedClash', 'conflict', events.SEVERE), '194': ('artillery', 'conflict', events.SEVERE), '195': ('airstrike', 'conflict', events.SEVERE),
    '196': ('ceasefireViolation', 'conflict', events.SEVERE),
    '200': ('massViolence', 'conflict', events.EXTREME), '201': ('expulsion', 'conflict', events.SEVERE), '202': ('massKilling', 'conflict', events.EXTREME),
    '203': ('massKilling', 'conflict', events.EXTREME), '204': ('massViolence', 'conflict', events.EXTREME),
}
LABEL = {'protest': 'Protest', 'hungerStrike': 'Hunger strike', 'strike': 'Strike', 'blockade': 'Blockade', 'riot': 'Riot',
         'crackdown': 'Crackdown', 'curfew': 'Curfew or sanction', 'massArrest': 'Arrests', 'expulsion': 'Expulsion', 'repression': 'Violent repression',
         'abduction': 'Abduction', 'assault': 'Assault', 'bombing': 'Bombing', 'assassination': 'Assassination', 'armedClash': 'Armed clash',
         'artillery': 'Artillery', 'airstrike': 'Air strike', 'ceasefireViolation': 'Ceasefire violation', 'massViolence': 'Mass violence', 'massKilling': 'Mass killing'}
PRECISION = {'1': 'country', '2': 'admin1', '3': 'admin1', '4': 'admin1', '5': 'admin1'}   # GDELT centroids are never a street address

COL = dict(id=0, day=1, root=28, base=27, code=26, goldstein=30, mentions=31, sources=32, articles=33, tone=34,
           gtype=51, gname=52, gcountry=53, gadm1=54, glat=56, glng=57, added=59, url=60)


def stamps_from(latest: str, n: int):
    """The n 15-minute stamps ending at `latest` (YYYYMMDDHHMMSS), newest first."""
    t = datetime.strptime(latest, '%Y%m%d%H%M%S').replace(tzinfo=timezone.utc)
    return [(t - timedelta(minutes=STEP_MIN * i)).strftime('%Y%m%d%H%M%S') for i in range(n)]


def latest_stamp() -> str:
    txt = get(BASE + 'lastupdate.txt', timeout=30).decode('utf-8', 'replace')
    m = re.search(r'/(\d{14})\.export\.CSV\.zip', txt)
    if not m:
        raise FeedError('lastupdate.txt names no export file')
    return m.group(1)


def rows_of(stamp: str):
    raw = get(f'{BASE}{stamp}.export.CSV.zip', timeout=60, retries=1)
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        name = z.namelist()[0]
        text = z.read(name).decode('utf-8', 'replace')
    for line in text.splitlines():
        r = line.split('\t')
        if len(r) >= 61:
            yield r


def wanted(r) -> bool:
    base = r[COL['base']]
    if base not in CODES:
        return False
    if r[COL['root']] != '14':
        try:
            if float(r[COL['goldstein']] or 0) > MIN_GOLDSTEIN_VIOLENCE:
                return False
        except ValueError:
            return False
    return bool(r[COL['glat']]) and bool(r[COL['glng']]) and r[COL['gtype']] in PRECISION


def key_of(r):
    return (r[COL['base']], round(float(r[COL['glat']]), 1), round(float(r[COL['glng']]), 1), r[COL['day']])


def collapse(rows, acc):
    """Sum the rows into acc[key] = {code, lat, lng, day, mentions, sources, articles, tone_sum, n, urls{url: mentions}, name, cc, adm1, added}."""
    for r in rows:
        if not wanted(r):
            continue
        k = key_of(r)
        a = acc.get(k)
        if a is None:
            a = acc[k] = {'code': r[COL['base']], 'lat': round(float(r[COL['glat']]), 3), 'lng': round(float(r[COL['glng']]), 3), 'day': r[COL['day']],
                          'mentions': 0, 'sources': 0, 'articles': 0, 'tone_sum': 0.0, 'n': 0, 'urls': {}, 'name': r[COL['gname']],
                          'cc': r[COL['gcountry']], 'adm1': r[COL['gadm1']], 'gtype': r[COL['gtype']], 'added': r[COL['added']]}
        try:
            a['mentions'] += int(r[COL['mentions']] or 0); a['sources'] += int(r[COL['sources']] or 0); a['articles'] += int(r[COL['articles']] or 0)
            a['tone_sum'] += float(r[COL['tone']] or 0)
        except ValueError:
            pass
        a['n'] += 1
        u = r[COL['url']]
        if u:
            a['urls'][u] = a['urls'].get(u, 0) + 1
        if r[COL['added']] > a['added']:
            a['added'] = r[COL['added']]


def record(a, at):
    kind, klass, sev = CODES[a['code']]
    cc = geocode.country_from_fips(a['cc']) if a['cc'] else None
    iso2 = cc['iso2'] if isinstance(cc, dict) else (cc if isinstance(cc, str) else None)
    top_url = max(a['urls'].items(), key=lambda kv: kv[1])[0] if a['urls'] else None
    domain = urlparse(top_url).netloc.replace('www.', '') if top_url else None
    added = datetime.strptime(a['added'], '%Y%m%d%H%M%S').replace(tzinfo=timezone.utc) if re.fullmatch(r'\d{14}', a['added'] or '') else at
    day = datetime.strptime(a['day'], '%Y%m%d').replace(tzinfo=timezone.utc)
    name = clip(a['name'] or (iso2 or 'unknown place'), 100)
    e = events.make(source='GDELT Events 2.0', source_tier='aggregator', kind=kind, threat_class=klass, severity=sev,
                    title=f'{LABEL[kind]} in {name}', headline=f'{a["mentions"]} mentions in {a["sources"]} sources' + (f' · {domain}' if domain else ''),
                    country_code=iso2, lat=a['lat'], lng=a['lng'], area=name, onset=day, updated=added, url=top_url,
                    facts=[['CAMEO', a['code']], ['Mentions', a['mentions']], ['Sources', a['sources']], ['Reports', a['n']],
                           ['Tone', round(a['tone_sum'] / max(1, a['n']), 1)], ['Geo', PRECISION[a['gtype']]]],
                    credit=CREDIT, licence=LICENCE, tags=['gdelt', 'cameo-' + a['code'][:2], kind],
                    source_id=f'{a["code"]}|{a["lat"]:.1f}|{a["lng"]:.1f}|{a["day"]}')
    e['geo_precision'] = PRECISION[a['gtype']]
    e['geo_radius_km'] = {'country': e['geo_radius_km'] if e['geo_radius_km'] else 300.0, 'admin1': 25.0}[e['geo_precision']]
    if iso2 in ('US', 'CA', 'AU') and a['adm1'] and len(a['adm1']) >= 4:
        st = geocode.state(a['adm1'][2:4], iso2)
        if st:
            e['admin1'], e['admin1_code'] = st['name'], st['code']
    e['corroboration'] = int(a['sources'])
    e['mentions'] = int(a['mentions'])
    # GDELT codes "fight" and "clash" out of metaphor as readily as out of war: a violence code from one or two
    # sources is a low-confidence report and drops one severity step; corroboration is the figure to read.
    e['confidence'] = 'high' if a['sources'] >= 5 else 'medium' if a['sources'] >= 2 else 'low'
    if a['code'][:2] in ('18', '19', '20') and a['sources'] < 3 and e['severity'] > events.MINOR:
        e['severity'] -= 1
        e['severity_label'] = events.SEVERITY_LABEL[e['severity']]
    return e


def compact(items):
    """The client file: one short array per record, in the order the web and the phone read."""
    rows = []
    for e in items:
        domain = urlparse(e['url']).netloc.replace('www.', '') if e.get('url') else None
        rows.append([e['id'][:16], e['kind'], e['threat_class'], e['severity'], e['lat'], e['lng'], e['geo_precision'], e.get('country_code'),
                     e.get('admin1_code'), e.get('area'), int(e.get('mentions') or 0), int(e.get('corroboration') or 0), (e.get('onset') or '')[:10],
                     domain, e.get('confidence'), e.get('facts', [[None, None]])[0][1]])
    return {'fields': ['id', 'kind', 'class', 'severity', 'lat', 'lng', 'precision', 'country', 'admin1', 'place', 'mentions', 'sources', 'day', 'domain', 'confidence', 'cameo'], 'rows': rows}


def main():
    at = now()
    prev = read_json(data_path('events.json')) or {}
    seen = list(prev.get('files_seen') or [])
    try:
        latest = latest_stamp()
    except FeedError as e:
        fail(str(e))
    todo = [s for s in stamps_from(latest, LOOKBACK_FILES) if s not in seen]
    acc = {}
    # the previous window's collapsed records are kept as-is (they are already sums); new files add new keys or new sums
    kept = [it for it in (prev.get('items') or []) if it.get('onset') and datetime.fromisoformat(it['onset'].replace('Z', '+00:00')) >= at - timedelta(hours=WINDOW_HOURS)]
    read = 0
    for s in sorted(todo):
        try:
            rows = list(rows_of(s))
        except FeedError as e:
            log(f'  {s}: {e}')
            continue
        read += 1
        collapse(rows, acc)
        seen.append(s)
    fresh = [record(a, at) for a in acc.values()]
    # merge: a fresh record replaces the kept one of the same id (same place, code and day), its counts folded in
    by_id = {it['id']: it for it in kept}
    for e in fresh:
        old = by_id.get(e['id'])
        if old:
            for f in e['facts']:
                if f[0] in ('Mentions', 'Sources', 'Reports'):
                    of = next((x for x in old.get('facts', []) if x[0] == f[0]), None)
                    f[1] = int(f[1]) + (int(of[1]) if of else 0)
            e['mentions'] = int(e['mentions']) + int(old.get('mentions') or 0)
            e['corroboration'] = int(e['corroboration']) + int(old.get('corroboration') or 0)
        by_id[e['id']] = e
    items = sorted(by_id.values(), key=lambda e: (-e['severity'], -(e.get('mentions') or 0)))[:MAX_ROWS]
    by_root = defaultdict(int)
    for e in items:
        by_root[e['tags'][1]] += 1
    log(f'GDELT events: {read} new files ({", ".join(sorted(todo)) or "none"}), {len(fresh)} fresh records, {len(items)} in the {WINDOW_HOURS} h window '
        f'({", ".join(f"{k} {v}" for k, v in sorted(by_root.items()))})')
    if read == 0 and prev:
        log('  nothing new upstream; keeping the last file')
        return
    extra = dict(upstream=BASE, credit=CREDIT, licence=LICENCE, notice=NOTICE, window_hours=WINDOW_HOURS, files_seen=sorted(seen)[-96:], latest=latest, by_root=dict(by_root))
    write_if_changed('events.json', envelope(items, **extra))
    write_if_changed('compact.json', envelope([], **dict(extra, **compact(items), count=len(items))))


if __name__ == '__main__':
    main()
