#!/usr/bin/env python3
"""US State Department travel advisories → data/advisories.json.

Upstream: https://travel.state.gov/_res/rss/TAsTWs.xml, every destination's current advisory (~220 items).
<category domain="Threat-Level"> holds the level and <category domain="Country-Tag"> a FIPS 10-4 code, not
ISO. The feed no longer carries indicator letters as categories, so they are read from the reasons in the
description's opening sentence. Public domain.

`levels` carries every destination once (the feed lists Tonga twice under two tags). `items` carries a
ThreatEvent for each one at Level 2 or above.
"""
import re

from tf import get_xml, rss_items, write_if_changed, envelope, parse_date, strip_html, log, fail, clip, FeedError
import events
import geocode

URL = 'https://travel.state.gov/_res/rss/TAsTWs.xml'
CREDIT = 'US Department of State, Travel Advisories'
LICENCE = 'US Government work, public domain'
INDICATORS = (('T', re.compile(r'terror', re.I)), ('U', re.compile(r'unrest|demonstration', re.I)),
              ('K', re.compile(r'kidnap|hostage', re.I)), ('D', re.compile(r'wrongful|detention|arbitrary arrest', re.I)),
              ('C', re.compile(r'crime', re.I)), ('H', re.compile(r'health|disease|medical', re.I)),
              ('N', re.compile(r'natural disaster', re.I)), ('E', re.compile(r'election', re.I)))
CONFLICT = re.compile(r'armed conflict|\bwar\b|\bconflict\b', re.I)
OPENING = re.compile(r'(?:do not travel|reconsider travel|exercise increased caution)[^.]*?\bdue to (?:the )?(?:risk of )?([^.]+)', re.I)
LABELS = {1: 'Exercise Normal Precautions', 2: 'Exercise Increased Caution', 3: 'Reconsider Travel', 4: 'Do Not Travel'}


def reasons_of(description):
    """The reasons in the advisory's opening sentence ("Do not travel to X due to the risk of a, b, and c"), which
    State writes as bold words, one bold list or plain text. Failing that, the section headings below it."""
    flat = ' '.join(strip_html(description or '').replace('U.S.', 'US').split())
    m = OPENING.search(flat)
    if m:
        parts = [re.sub(r'^and\s+', '', p.strip(' .,')) for p in m.group(1).split(',')]
    else:
        parts = [strip_html(h) for h in re.findall(r'<h5[^>]*>(.*?)</h5>', description or '', flags=re.S)]
    return [p for p in parts if p and len(p) < 80]


def indicators_of(reasons):
    letters = []
    for reason in reasons:
        hits = [letter for letter, rx in INDICATORS if rx.search(reason)]
        letters += hits or ['O']
    return list(dict.fromkeys(letters))


def class_of(reasons, letters):
    if 'T' in letters:
        return 'terrorism'
    if any(CONFLICT.search(r) for r in reasons):
        return 'conflict'
    if 'U' in letters:
        return 'unrest'
    if set(letters) & {'K', 'D', 'C'}:
        return 'crime'
    return 'unknown'


def severity_of(level, reasons, letters):
    """The taxonomy's advisory row: Level 4 for security reasons SEVERE, Level 4 otherwise and Level 3 MODERATE."""
    if level == 4 and (set(letters) & {'T', 'U', 'K', 'D'} or any(CONFLICT.search(r) for r in reasons)):
        return events.SEVERE
    return {4: events.MODERATE, 3: events.MODERATE, 2: events.MINOR}.get(level, events.INFO)


def decode(root):
    levels, items, seen = [], [], set()
    for it in rss_items(root):
        title = it['title'] or ''
        level, fips = None, None
        for domain, text in it['categories']:
            if domain == 'Threat-Level':
                m = re.search(r'Level\s+(\d)', text or '')
                level = int(m.group(1)) if m else None
            elif domain == 'Country-Tag':
                fips = (text or '').strip().upper() or None
        if level is None:
            m = re.search(r'Level\s+(\d)', title)
            level = int(m.group(1)) if m else None
        name = title.split(' - ')[0].strip()
        named = geocode.find_countries(name)                           # the title names the country
        place = named[0] if named else geocode.country_from_fips(fips)  # the tag is FIPS 10-4, not ISO
        iso2 = place['iso2'] if place else None
        if (iso2, name) in seen:
            continue
        seen.add((iso2, name))
        reasons = reasons_of(it['description'])
        letters = indicators_of(reasons)
        published = parse_date(it['pubDate'])
        url = it['link'] or it['guid']
        levels.append({'country': name, 'iso2': iso2, 'fips': fips, 'government': 'us', 'level': level, 'title': title,
                       'indicators': letters, 'reasons': reasons,
                       'updated': published.strftime('%Y-%m-%d') if published else None, 'url': url})
        if level is None or level < 2:
            continue
        items.append(events.make(
            source='US State Department', source_tier='official', kind='advisory',
            threat_class=class_of(reasons, letters), severity=severity_of(level, reasons, letters),
            title=title, headline=f'Level {level}: {LABELS.get(level, "")}'.strip(' :'),
            body=clip(strip_html(it['description']), 500), country_code=iso2, area=name if not iso2 else None,
            updated=published, url=url,
            facts=[['Level', str(level)], ['Indicators', ' '.join(letters) or '—'], ['Reasons', ', '.join(reasons) or '—']],
            credit=CREDIT, licence=LICENCE, tags=['travel-advisory'] + [f'{x.lower()}-indicator' for x in letters], source_id=url))
    items.sort(key=lambda e: (-e['severity'], e['title']))
    return levels, items


def main():
    try:
        root = get_xml(URL, timeout=90)
    except FeedError as e:
        fail(str(e))
    levels, items = decode(root)
    if len(levels) < 100:
        fail(f'State Department feed decoded to only {len(levels)} advisories')
    unmatched = [r['country'] for r in levels if not r['iso2']]
    by_level = {str(n): sum(1 for r in levels if r['level'] == n) for n in (1, 2, 3, 4)}
    upstream_count = sum(1 for _ in root.iter('item'))
    log(f'State Department: {upstream_count} upstream, {len(levels)} destinations {by_level}, {len(items)} events, unmatched: {unmatched}')
    write_if_changed('advisories.json', envelope(items, upstream=URL, credit=CREDIT, licence=LICENCE, total=len(levels),
                                                 upstream_count=upstream_count, by_level=by_level, unmatched=unmatched, levels=levels))


if __name__ == '__main__':
    main()
