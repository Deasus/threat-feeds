#!/usr/bin/env python3
"""CISA ICS advisories → data/ics.json.

Upstream: CISA's CSAF ROLIE feed for OT advisories on github.com/cisagov/CSAF (TLP:WHITE, listed in CISA's
provider-metadata.json). The cisa.gov RSS carries the same advisories but answers 403 to datacentre clients,
GitHub's runners included, so this feed never reads it.

Each advisory revised in the last 45 days becomes a ThreatEvent. The per-advisory document gives vendor,
products, CVEs, CVSS and sectors; it is fetched once and reused from the previous file until CISA revises it.
Severity follows the taxonomy: a CERT advisory is MINOR.
"""
from datetime import timedelta

from tf import get_json, read_json, data_path, write_if_changed, envelope, parse_date, now, log, fail, first_sentence, FeedError
import events

URL = 'https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json'
CREDIT = 'CISA ICS Advisories'
LICENCE = 'US Government work, public domain; CISA notification terms; no CISA logo'
WINDOW_DAYS = 45
MAX_ERRORS = 5

# CISA's "Critical infrastructure sectors" note → the taxonomy's target_sector
SECTORS = {
    'chemical': 'chemical', 'commercial facilities': 'commercialFacilities', 'communications': 'communications',
    'critical manufacturing': 'criticalManufacturing', 'dams': 'dams', 'defense industrial base': 'defenseIndustrialBase',
    'emergency services': 'emergencyServices', 'energy': 'energy', 'financial services': 'financialServices',
    'food and agriculture': 'foodAgriculture', 'government services and facilities': 'government',
    'government facilities': 'government', 'healthcare and public health': 'healthcare',
    'information technology': 'informationTechnology', 'nuclear reactors, materials, and waste': 'nuclear',
    'transportation systems': 'transportation', 'water and wastewater': 'water',
    'water and wastewater systems': 'water',
}


def recent(feed, at):
    """ROLIE entries revised inside the window, newest first: [(id, updated, document url)]."""
    cut = at - timedelta(days=WINDOW_DAYS)
    out = []
    for e in (feed.get('feed') or {}).get('entry') or []:
        updated = parse_date(e.get('updated') or e.get('published'))
        src = (e.get('content') or {}).get('src')
        if e.get('id') and src and updated and updated >= cut:
            out.append((e['id'], e.get('updated') or e.get('published'), src))
    return sorted(out, key=lambda r: r[1], reverse=True)


def _sectors(text):
    """Taxonomy slugs for the sectors CISA names; longest names first, since some hold commas of their own."""
    text, out = (text or '').lower(), []
    for name in sorted(SECTORS, key=len, reverse=True):
        if name in text:
            text = text.replace(name, '')
            if SECTORS[name] not in out:
                out.append(SECTORS[name])
    return out


def _products(tree):
    """'Vendor Product' strings from the CSAF product tree, one per named product."""
    out = []
    for vendor in tree.get('branches') or []:
        names = [b.get('name') for b in vendor.get('branches') or [] if b.get('category') == 'product_name']
        out += [f'{vendor.get("name")} {n}' for n in names] or [vendor.get('name')]
    return [p for p in dict.fromkeys(out) if p][:20]


def _max_cvss(vulns):
    scores = []
    for v in vulns:
        for s in v.get('scores') or []:
            for key in ('cvss_v4', 'cvss_v3', 'cvss_v2'):
                if (s.get(key) or {}).get('baseScore') is not None:
                    scores.append(float(s[key]['baseScore']))
    return max(scores) if scores else None


def decode_doc(doc, url):
    """One CSAF document → ThreatEvent."""
    d = doc['document']
    tracking = d.get('tracking') or {}
    advisory = tracking.get('id')
    notes = {}
    for n in d.get('notes') or []:
        notes.setdefault(n.get('title'), n.get('text'))
    sectors = _sectors(notes.get('Critical infrastructure sectors'))
    vulns = doc.get('vulnerabilities') or []
    cves = sorted({v['cve'] for v in vulns if v.get('cve')})
    cvss = _max_cvss(vulns)
    page = next((r.get('url') for r in d.get('references') or [] if (r.get('url') or '').startswith('https://www.cisa.gov/news-events/ics')), url)
    vendors = [b.get('name') for b in (doc.get('product_tree') or {}).get('branches') or [] if b.get('name')]
    return events.make(
        source='CISA ICS', source_tier='official', kind='cyberAdvisory', threat_class='cyber', severity=events.MINOR,
        title=d.get('title') or advisory, headline=advisory,
        body=first_sentence(notes.get('Summary') or ''),
        target_sector=sectors[0] if sectors else None, cve_ids=cves, cvss=cvss, products=_products(doc.get('product_tree') or {}),
        onset=parse_date(tracking.get('initial_release_date')), updated=parse_date(tracking.get('current_release_date')), url=page,
        facts=[['Advisory', advisory or '—'], ['Vendor', ', '.join(vendors) or '—'],
               ['Max CVSS', str(cvss) if cvss is not None else '—'],
               ['Sectors', notes.get('Critical infrastructure sectors') or '—'],
               ['Deployed', notes.get('Countries/areas deployed') or '—'],
               ['Vendor HQ', notes.get('Company headquarters location') or '—']],
        credit=CREDIT, licence=LICENCE, tags=['ics', 'ot'] + sectors[1:] + [c.lower() for c in cves], source_id=advisory)


def fact(ev, label):
    return next((v for k, v in ev.get('facts') or [] if k == label), None)


def main():
    try:
        feed = get_json(URL, timeout=90)
    except FeedError as e:
        fail(str(e))
    wanted = recent(feed, now())
    if not wanted:
        fail('CSAF OT feed has no advisory revised in the window')
    old = {fact(e, 'Advisory'): e for e in (read_json(data_path('ics.json')) or {}).get('items') or []}
    items, fetched, errors = [], 0, 0
    for advisory, updated, src in wanted:
        prev = old.get(advisory)
        if prev and parse_date(prev.get('updated')) == parse_date(updated):
            items.append(prev)
            continue
        try:
            items.append(decode_doc(get_json(src, timeout=30), src))
            fetched += 1
        except (FeedError, KeyError, TypeError, ValueError) as e:
            errors += 1
            log(f'  {advisory}: {str(e)[:120]}')
            if prev:
                items.append(prev)
            if errors > MAX_ERRORS:
                fail(f'{errors} advisory documents failed')
    entries = (feed.get('feed') or {}).get('entry') or []
    cut = now() - timedelta(days=7)
    log(f'CISA ICS: {len(entries)} in the feed, {len(items)} in the window, {fetched} fetched, {errors} errors')
    write_if_changed('ics.json', envelope(items, upstream=URL, credit=CREDIT, licence=LICENCE, total=len(entries),
                                          published_7d=sum(1 for e in entries if (parse_date(e.get('published')) or cut) > cut)))


if __name__ == '__main__':
    main()
