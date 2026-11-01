#!/usr/bin/env python3
"""CISA Known Exploited Vulnerabilities → data/kev.json.

Upstream: the KEV catalogue JSON (CC0 1.0; never use the CISA logo).
`catalog` carries every entry; `items` carries a ThreatEvent for each addition in the last 45 days.
Severity follows the taxonomy: an addition flagged "known ransomware use" is SEVERE, any other MODERATE.
"""
from datetime import timedelta

from tf import get_json, write_if_changed, envelope, parse_date, now, log, fail, clip, FeedError
import events

URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
CREDIT = 'CISA Known Exploited Vulnerabilities Catalog'
LICENCE = 'CC0 1.0; no CISA logo'
WINDOW_DAYS = 45


def decode(doc, at):
    """(catalog rows, ThreatEvents, stats) from the upstream document, as of the datetime `at`."""
    catalog, items = [], []
    ransomware = added_7d = 0
    for v in doc.get('vulnerabilities') or []:
        cve = v.get('cveID')
        if not cve:
            continue
        added = parse_date(v.get('dateAdded'))
        known = str(v.get('knownRansomwareCampaignUse', '')).strip().lower() == 'known'
        vendor, product = v.get('vendorProject') or '', v.get('product') or ''
        summary = clip(v.get('shortDescription'), 400)
        catalog.append({'cve_id': cve, 'vendor': vendor, 'product': product, 'name': v.get('vulnerabilityName'),
                        'date_added': v.get('dateAdded'), 'due_date': v.get('dueDate'),
                        'known_ransomware_use': known, 'cwes': v.get('cwes') or [], 'summary': summary})
        ransomware += known
        if added is None:
            continue
        added_7d += added >= at - timedelta(days=7)
        if added < at - timedelta(days=WINDOW_DAYS):
            continue
        tags = ['kev', cve.lower()] + (['ransomware'] if known else [])
        items.append(events.make(
            source='CISA KEV', source_tier='official', kind='kevAddition', threat_class='cyber',
            severity=events.SEVERE if known else events.MODERATE,
            title=f'{cve}: {" ".join(x for x in (vendor, product) if x)}'.strip(' :'),
            headline=v.get('vulnerabilityName'), body=summary, instruction=clip(v.get('requiredAction'), 300),
            cve_ids=[cve], kev=True, known_ransomware_use=known,
            products=[' '.join(x for x in (vendor, product) if x)] if vendor or product else [],
            onset=added, updated=added,
            facts=[['Added', v.get('dateAdded') or '—'], ['Due', v.get('dueDate') or '—'],
                   ['Known ransomware use', 'yes' if known else 'not known']],
            credit=CREDIT, licence=LICENCE, tags=tags, source_id=cve))
    items.sort(key=lambda e: (e['updated'] or '', e['id']), reverse=True)
    return catalog, items, {'ransomware_known': ransomware, 'added_7d': added_7d}


def main():
    try:
        doc = get_json(URL, timeout=60)
    except FeedError as e:
        fail(str(e))
    catalog, items, stats = decode(doc, now())
    if len(catalog) < 1000:
        fail(f'KEV decoded to only {len(catalog)} entries')
    log(f'CISA KEV: {len(catalog)} entries, {stats["ransomware_known"]} ransomware, {stats["added_7d"]} added in 7 d, '
        f'{len(items)} events')
    write_if_changed('kev.json', envelope(items, upstream=URL, credit=CREDIT, licence=LICENCE,
                                          catalog_version=doc.get('catalogVersion'), total=len(catalog),
                                          catalog=catalog, **stats))


if __name__ == '__main__':
    main()
