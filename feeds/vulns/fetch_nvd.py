#!/usr/bin/env python3
"""NVD critical CVEs → data/critical.json.

Upstream: NVD CVE API 2.0, read without a key (5 requests per 30 s), so pages are spaced 6.5 s apart.
Each run asks only for what changed since the last run (state.json keeps the mark), three days on the
first run, and reads every page of the answer.

A side table, never an event feed: `rows` holds CVEs published in the last 30 days with CVSS ≥ 9 and
vendor/product strings; `items` stays empty on purpose. Rejected CVEs are dropped. CVEs without a score
yet are dropped until NVD or the CNA scores them.
"""
import json
import os
import time
import urllib.parse
from datetime import timedelta

from tf import get_json, read_json, data_path, write_if_changed, envelope, parse_date, now, iso, log, fail, clip, DATA, FeedError

URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
CREDIT = 'NIST National Vulnerability Database'
LICENCE = 'US Government work; attribution'
NOTICE = 'This product uses data from the NVD API but is not endorsed or certified by the NVD.'
FIRST_WINDOW_DAYS = 3
KEEP_DAYS = 30
CRITICAL = 9.0
PAGE_SIZE = 2000
PAGE_GAP = 6.5
OVERLAP = timedelta(hours=1)
METRICS = ('cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2')


def score(cve):
    """(base score, CVSS version, severity) from the newest CVSS version present, NVD's own rating first."""
    metrics = cve.get('metrics') or {}
    for key in METRICS:
        rows = metrics.get(key) or []
        if rows:
            row = next((r for r in rows if r.get('type') == 'Primary'), rows[0])
            data = row.get('cvssData') or {}
            if data.get('baseScore') is not None:
                return float(data['baseScore']), data.get('version'), (data.get('baseSeverity') or row.get('baseSeverity') or '').upper()
    return None, None, ''


def affected(cve):
    """(vendors, 'vendor product' strings) from the CPE matches marked vulnerable."""
    vendors, products = [], []
    for config in cve.get('configurations') or []:
        for node in config.get('nodes') or []:
            for match in node.get('cpeMatch') or []:
                parts = (match.get('criteria') or '').split(':')
                if match.get('vulnerable') and len(parts) > 4:
                    vendors.append(parts[3])
                    products.append(f'{parts[3]} {parts[4]}')
    return list(dict.fromkeys(vendors))[:12], list(dict.fromkeys(products))[:12]


def row_of(cve):
    """One side-table row, or None when the CVE is rejected, unscored or below critical."""
    if str(cve.get('vulnStatus')).lower() == 'rejected':
        return None
    base, version, severity = score(cve)
    if base is None or base < CRITICAL:
        return None
    vendors, products = affected(cve)
    summary = next((d.get('value') for d in cve.get('descriptions') or [] if d.get('lang') == 'en'), '')
    cwes = [d.get('value') for w in cve.get('weaknesses') or [] for d in w.get('description') or [] if d.get('lang') == 'en']
    return {'cve_id': cve.get('id'), 'cvss': base, 'cvss_version': version, 'severity': severity or 'CRITICAL',
            'published': iso(parse_date(cve.get('published'))), 'last_modified': iso(parse_date(cve.get('lastModified'))),
            'status': cve.get('vulnStatus'), 'kev': bool(cve.get('cisaExploitAdd')), 'vendors': vendors,
            'products': products, 'cwes': list(dict.fromkeys(c for c in cwes if c))[:6], 'summary': clip(summary, 400)}


def tally(cves):
    counts = {'total': 0, 'critical': 0, 'high': 0, 'rejected': 0}
    for cve in cves:
        counts['total'] += 1
        counts['rejected'] += str(cve.get('vulnStatus')).lower() == 'rejected'
        severity = score(cve)[2]
        counts['critical'] += severity == 'CRITICAL'
        counts['high'] += severity == 'HIGH'
    return counts


def merge(old_rows, new_rows, at):
    """Previous rows updated by this window's, dropping anything older than the keep window, highest score first."""
    rows = {r['cve_id']: r for r in old_rows}
    rows.update({r['cve_id']: r for r in new_rows})
    cut = at - timedelta(days=KEEP_DAYS)
    kept = [r for r in rows.values() if (parse_date(r['published']) or at) >= cut]
    return sorted(kept, key=lambda r: (-r['cvss'], r['cve_id']))


def stamp(dt) -> str:
    return dt.strftime('%Y-%m-%dT%H:%M:%S.000')


def fetch_window(start, end):
    """Every CVE modified between start and end, across as many pages as the answer has."""
    cves, index = [], 0
    while True:
        query = urllib.parse.urlencode({'lastModStartDate': stamp(start), 'lastModEndDate': stamp(end),
                                        'resultsPerPage': PAGE_SIZE, 'startIndex': index}, safe=':')
        page = get_json(f'{URL}?{query}', timeout=120)
        rows = page.get('vulnerabilities') or []
        cves += [r.get('cve') or {} for r in rows]
        total = page.get('totalResults', len(cves))
        index += len(rows)
        if not rows or index >= total:
            return cves, total
        time.sleep(PAGE_GAP)


def main():
    at = now()
    mark = parse_date((read_json(data_path('state.json')) or {}).get('last_mod_end'))
    start = max(mark - OVERLAP, at - timedelta(days=KEEP_DAYS)) if mark else at - timedelta(days=FIRST_WINDOW_DAYS)
    try:
        cves, total = fetch_window(start, at)
    except FeedError as e:
        fail(str(e))
    if len(cves) != total:
        fail(f'NVD promised {total} CVEs and returned {len(cves)}')
    counts = tally(cves)
    fresh = [r for r in (row_of(c) for c in cves) if r]
    rows = merge((read_json(data_path('critical.json')) or {}).get('rows') or [], fresh, at)
    log(f'NVD: {counts["total"]} modified since {iso(start)} ({counts["critical"]} critical, {counts["high"]} high, '
        f'{counts["rejected"]} rejected); {len(rows)} rows kept')
    write_if_changed('critical.json', envelope([], upstream=URL, credit=CREDIT, licence=LICENCE, notice=NOTICE,
                                               keep_days=KEEP_DAYS, row_count=len(rows), rows=rows))
    os.makedirs(DATA, exist_ok=True)
    with open(data_path('state.json'), 'w', encoding='utf-8') as f:
        json.dump({'last_mod_end': iso(at), 'window': dict(counts, start=iso(start), end=iso(at))}, f)


if __name__ == '__main__':
    main()
