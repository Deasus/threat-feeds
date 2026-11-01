#!/usr/bin/env python3
"""GDACS Orange and Red disaster alerts → data/gdacs.json.

Upstream: the GDACS event list API, keyless. An unfiltered list reaches back about a year, and GDACS's own
`iscurrent` flag marks very few events, so a ThreatEvent is kept while its end date is inside the last 45
days; `upstream_count` and `current_count` stay in the file so the difference is visible.

Every GDACS coordinate is a centroid. An earthquake's epicentre and a volcano's vent are real points; a
cyclone, flood, fire or drought is drawn at the country with its ring, and one spanning several countries
carries `countries[]` and no position, never a pin in the wrong place. Red is SEVERE, Orange is MODERATE.

GDACS notifications are automatic and unreviewed, so `notice` travels with the data. GDACS's terms state no
reuse licence of their own; they link the European Commission's notice (CC BY 4.0 for EU-owned content).
"""
from datetime import timedelta

from tf import get_json, write_if_changed, envelope, parse_date, now, log, fail, clip, FeedError
import events

URL = ('https://www.gdacs.org/gdacsapi/api/events/geteventlist/SEARCH'
       '?fromDate=&toDate=&alertlevel=Orange;Red&eventlist=EQ;TC;FL;VO;DR;WF')
CREDIT = 'GDACS, Global Disaster Alert and Coordination System (UN, European Commission)'
LICENCE = 'GDACS terms of use; European Commission reuse notice, CC BY 4.0 for EU-owned content (to be confirmed)'
NOTICE = ('GDACS notifications are automatic estimates that may contain errors. They do not replace alerts from '
          'local or national authorities and need confirming before any decision.')
WINDOW_DAYS = 45
KINDS = {'EQ': 'earthquake', 'TC': 'cyclone', 'FL': 'flood', 'VO': 'volcano', 'DR': 'drought', 'WF': 'wildfire'}
POINT_KINDS = ('EQ', 'VO')
SEVERITY = {'red': events.SEVERE, 'orange': events.MODERATE}


def decode(doc, at):
    """(ThreatEvents, stats) as of the datetime `at`."""
    feats = doc.get('features') or []
    items = []
    red = orange = current = 0
    for f in feats:
        p = f.get('properties') or {}
        level = (p.get('alertlevel') or '').lower()
        red += level == 'red'
        orange += level == 'orange'
        current += str(p.get('iscurrent')).lower() == 'true'
        kind = KINDS.get(p.get('eventtype'))
        ended = parse_date(p.get('todate'))
        if kind is None or level not in SEVERITY or ended is None or ended < at - timedelta(days=WINDOW_DAYS):
            continue
        iso2s = [c['iso2'] for c in p.get('affectedcountries') or [] if c.get('iso2')]
        coords = (f.get('geometry') or {}).get('coordinates') or []
        lng, lat = (coords[0], coords[1]) if p.get('eventtype') in POINT_KINDS and len(coords) >= 2 else (None, None)
        urls = p.get('url') if isinstance(p.get('url'), dict) else {}
        severity_text = (p.get('severitydata') or {}).get('severitytext') or ''
        items.append(events.make(
            source='GDACS', source_tier='aggregator', kind=kind, threat_class='disruption', severity=SEVERITY[level],
            title=clip((p.get('name') or p.get('eventname') or kind).strip(' ,'), 120), headline=clip(severity_text, 200),
            country_code=iso2s[0] if len(iso2s) == 1 else None, countries=iso2s, lat=lat, lng=lng,
            area=clip((p.get('country') or '').strip(' ,'), 120) or None if len(iso2s) != 1 else None,
            onset=parse_date(p.get('fromdate')), updated=parse_date(p.get('datemodified')) or ended,
            expires=None, url=urls.get('report'),
            facts=[['Alert', p.get('alertlevel') or '—'], ['Impact', severity_text or '—'],
                   ['From', (p.get('fromdate') or '')[:10] or '—'], ['To', (p.get('todate') or '')[:10] or '—'],
                   ['GLIDE', p.get('glide') or '—']],
            credit=CREDIT, licence=LICENCE, tags=['natural-hazard', kind] + (['current'] if str(p.get('iscurrent')).lower() == 'true' else []),
            source_id=f'{p.get("eventtype")}-{p.get("eventid")}'))
    items.sort(key=lambda e: (-e['severity'], e['updated'] or '', e['id']))
    return items, {'upstream_count': len(feats), 'red': red, 'orange': orange, 'current_count': current}


def main():
    try:
        doc = get_json(URL, timeout=60)
    except FeedError as e:
        fail(str(e))
    if 'features' not in doc:
        fail('GDACS answer has no features list')
    items, stats = decode(doc, now())
    log(f'GDACS: {stats["upstream_count"]} upstream ({stats["red"]} red, {stats["orange"]} orange, '
        f'{stats["current_count"]} current), {len(items)} in the window')
    write_if_changed('gdacs.json', envelope(items, upstream=URL, credit=CREDIT, licence=LICENCE, notice=NOTICE,
                                            window_days=WINDOW_DAYS, **stats))


if __name__ == '__main__':
    main()
