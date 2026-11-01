#!/usr/bin/env python3
"""USGS significant earthquakes, past week → data/quakes.json.

Upstream: the USGS GeoJSON summary feed, keyless. US Government work, public domain.
The epicentre is a real point. Severity from PAGER and magnitude: M ≥ 7 or PAGER orange/red is SEVERE,
M ≥ 6, PAGER yellow or a tsunami flag is MODERATE, anything else on this list is MINOR.
"""
from datetime import datetime, timezone

from tf import get_json, write_if_changed, envelope, log, fail, FeedError
import events
import geocode

URL = 'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/significant_week.geojson'
CREDIT = 'U.S. Geological Survey, Earthquake Hazards Program'
LICENCE = 'US Government work, public domain'


def severity_of(mag, pager, tsunami):
    pager = (pager or '').lower()
    if mag >= 7 or pager in ('orange', 'red'):
        return events.SEVERE
    if mag >= 6 or pager == 'yellow' or tsunami:
        return events.MODERATE
    return events.MINOR


def stamp(ms):
    return datetime.fromtimestamp(ms / 1000, timezone.utc) if ms else None


def decode(doc):
    items = []
    for f in doc.get('features') or []:
        p = f.get('properties') or {}
        coords = (f.get('geometry') or {}).get('coordinates') or []
        if p.get('mag') is None or len(coords) < 2:
            continue
        mag = float(p['mag'])
        place = p.get('place') or 'unknown location'
        named = geocode.find_countries(place)
        tsunami = bool(p.get('tsunami'))
        items.append(events.make(
            source='USGS', source_tier='official', kind='earthquake', threat_class='disruption',
            severity=severity_of(mag, p.get('alert'), tsunami), title=f'M{mag:g} {place}',
            headline=f'PAGER {p["alert"]}' if p.get('alert') else None,
            area=place, lat=coords[1], lng=coords[0], countries=[c['iso2'] for c in named[:1]],
            onset=stamp(p.get('time')), updated=stamp(p.get('updated')) or stamp(p.get('time')), url=p.get('url'),
            facts=[['Magnitude', f'{mag:g}'], ['Depth', f'{coords[2]:g} km' if len(coords) > 2 and coords[2] is not None else '—'],
                   ['PAGER', p.get('alert') or '—'], ['Tsunami flag', 'yes' if tsunami else 'no']],
            credit=CREDIT, licence=LICENCE, tags=['natural-hazard', 'earthquake'] + (['tsunami'] if tsunami else []),
            source_id=f.get('id')))
    items.sort(key=lambda e: (-e['severity'], e['title']))
    return items


def main():
    try:
        doc = get_json(URL, timeout=30)
    except FeedError as e:
        fail(str(e))
    if 'features' not in doc:
        fail('USGS answer has no features list')
    items = decode(doc)
    log(f'USGS: {len(items)} significant earthquakes in 7 d')
    write_if_changed('quakes.json', envelope(items, upstream=URL, credit=CREDIT, licence=LICENCE))


if __name__ == '__main__':
    main()
