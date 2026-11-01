"""Decoder tests on captured fixtures (no network). Run: python3 -m unittest discover -s tests -q"""
import copy
import importlib
import json
import os
import sys
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEEDS = os.path.join(ROOT, 'feeds')
FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fixtures')
for d in ['_shared', 'cisa', 'vulns', 'travel', 'hazards']:
    sys.path.insert(0, os.path.join(FEEDS, d))
sys.path.insert(0, ROOT)

tf = importlib.import_module('tf')
events = importlib.import_module('events')
kev = importlib.import_module('fetch_kev')
ics = importlib.import_module('fetch_ics')
nvd = importlib.import_module('fetch_nvd')
state = importlib.import_module('fetch_state')
gdacs = importlib.import_module('fetch_gdacs')
usgs = importlib.import_module('fetch_usgs')
conductor = importlib.import_module('conductor')
NOW = datetime(2026, 11, 1, 2, 0, tzinfo=timezone.utc)

# PLAN §4.4: the record every client decodes
THREAT_EVENT_FIELDS = {
    'id', 'kind', 'threat_class', 'severity', 'severity_label', 'source', 'source_tier', 'title', 'headline', 'body',
    'instruction', 'actor', 'actor_name', 'actor_type', 'target_sector', 'target_type', 'area', 'country_code', 'countries',
    'admin1', 'admin1_code', 'lat', 'lng', 'geo_precision', 'geo_radius_km', 'region', 'fatalities', 'injuries',
    'casualties_quote', 'records', 'cve_ids', 'cvss', 'epss', 'kev', 'known_ransomware_use', 'products', 'onset', 'updated',
    'expires', 'url', 'facts', 'credit', 'licence', 'tags', 'corroboration', 'cluster'}


def load_json(name):
    with open(os.path.join(FIX, name), encoding='utf-8') as f:
        return json.load(f)


def state_rows():
    return state.decode(ET.parse(os.path.join(FIX, 'state.xml')).getroot())


class Dates(unittest.TestCase):
    def test_every_upstream_date_shape(self):
        for raw, want in (('Thu, 27 Aug 2026', '2026-08-27T00:00:00Z'),            # State Department: no time of day
                          ('Tue, 27 Oct 2026 12:00:00 EDT', '2026-10-27T16:00:00Z'),
                          ('2026-10-27T00:00:00.000000Z', '2026-10-27T00:00:00Z'),  # CSAF
                          ('2026-10-30T12:15:33.123', '2026-10-30T12:15:33Z'),      # NVD
                          ('2025-12-21T00:00:00', '2025-12-21T00:00:00Z'),          # GDACS
                          ('2026-10-31T21:29:02Z', '2026-10-31T21:29:02Z'),
                          ('2026-10-30', '2026-10-30T00:00:00Z')):
            self.assertEqual(tf.iso(tf.parse_date(raw)), want, raw)
        self.assertIsNone(tf.parse_date('not a date'))
        self.assertIsNone(tf.parse_date(None))


class Record(unittest.TestCase):
    def test_every_feed_emits_the_full_record(self):
        rows = kev.decode(load_json('kev.json'), NOW)[1] + state_rows()[1] + gdacs.decode(load_json('gdacs.json'), NOW)[0] \
            + usgs.decode(load_json('usgs.json')) + [ics.decode_doc(load_json('csaf_doc.json'), 'u')]
        self.assertTrue(rows)
        for e in rows:
            self.assertEqual(set(e), THREAT_EVENT_FIELDS, e['title'])
            self.assertIn(e['geo_precision'], events.PRECISION)
            self.assertEqual(e['severity_label'], events.SEVERITY_LABEL[e['severity']])
            self.assertTrue(e['credit'] and e['licence'] and e['updated'], e['title'])
            if e['geo_precision'] == 'none':
                self.assertIsNone(e['lat'])

    def test_a_country_without_a_position_gets_its_centroid_and_a_ring(self):
        e = events.make(source='s', source_tier='official', kind='advisory', threat_class='unknown', title='t',
                        updated=NOW, country_code='NE')
        self.assertEqual(e['geo_precision'], 'country')
        self.assertIsNotNone(e['lat'])
        self.assertGreater(e['geo_radius_km'], 0)

    def test_an_unknown_kind_is_refused(self):
        with self.assertRaises(AssertionError):
            events.make(source='s', source_tier='official', kind='nope', threat_class='cyber', title='t', updated=NOW)


class Kev(unittest.TestCase):
    def test_catalog_keeps_every_entry_and_events_only_the_window(self):
        doc = load_json('kev.json')
        catalog, items, stats = kev.decode(doc, NOW)
        self.assertEqual(len(catalog), len(doc['vulnerabilities']))
        self.assertEqual(len(items), 2)
        self.assertEqual(stats['ransomware_known'], sum(v['knownRansomwareCampaignUse'] == 'Known' for v in doc['vulnerabilities']))
        self.assertTrue(all(e['kev'] and e['cve_ids'] and e['kind'] == 'kevAddition' for e in items))

    def test_severity_follows_the_ransomware_flag(self):
        doc = load_json('kev.json')
        doc['vulnerabilities'][0]['knownRansomwareCampaignUse'] = 'Known'
        by_cve = {e['cve_ids'][0]: e for e in kev.decode(doc, NOW)[1]}
        first, second = (v['cveID'] for v in doc['vulnerabilities'][:2])
        self.assertEqual(by_cve[first]['severity'], events.SEVERE)
        self.assertTrue(by_cve[first]['known_ransomware_use'])
        self.assertEqual(by_cve[second]['severity'], events.MODERATE)


class Ics(unittest.TestCase):
    def test_recent_keeps_the_window_newest_first(self):
        rows = ics.recent(load_json('csaf_feed.json'), NOW)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows, sorted(rows, key=lambda r: r[1], reverse=True))

    def test_document_fields(self):
        e = ics.decode_doc(load_json('csaf_doc.json'), 'fallback')
        self.assertEqual(e['headline'], 'ICSA-26-302-03')
        self.assertEqual(e['target_sector'], 'energy')
        self.assertEqual(e['severity'], events.MINOR)
        self.assertEqual(e['cvss'], 8.8)
        self.assertEqual(len(e['cve_ids']), 2)
        self.assertTrue(e['url'].startswith('https://www.cisa.gov/news-events/ics'))
        self.assertTrue(all(p.startswith('Hitachi Energy') for p in e['products']))
        self.assertEqual(e['updated'], '2026-10-29T06:00:00Z')
        self.assertEqual(ics.fact(e, 'Advisory'), 'ICSA-26-302-03')

    def test_sector_names_with_their_own_commas(self):
        self.assertEqual(ics._sectors('Nuclear Reactors, Materials, and Waste'), ['nuclear'])
        self.assertEqual(sorted(ics._sectors('Energy, Water and Wastewater Systems')), ['energy', 'water'])
        self.assertEqual(ics._sectors(None), [])


class Nvd(unittest.TestCase):
    def setUp(self):
        self.cves = {v['cve']['id']: v['cve'] for v in load_json('nvd.json')['vulnerabilities']}

    def test_a_critical_row_carries_vendor_and_product(self):
        r = nvd.row_of(self.cves['CVE-2026-69399'])
        self.assertGreaterEqual(r['cvss'], nvd.CRITICAL)
        self.assertTrue(r['vendors'] and r['products'])
        self.assertTrue(r['summary'])

    def test_high_unscored_and_rejected_are_left_out(self):
        self.assertIsNone(nvd.row_of(self.cves['CVE-2026-102212']))
        self.assertIsNone(nvd.row_of(self.cves['CVE-2026-78188']))
        rejected = copy.deepcopy(self.cves['CVE-2026-69399'])
        rejected['vulnStatus'] = 'Rejected'
        self.assertIsNone(nvd.row_of(rejected))

    def test_cvss_v4_is_read(self):
        self.assertEqual(nvd.score(self.cves['CVE-2026-102212'])[1], '4.0')

    def test_merge_keeps_recent_rows_and_drops_old_ones(self):
        recent = nvd.row_of(self.cves['CVE-2026-69399'])
        at = tf.parse_date(recent['published']) + timedelta(days=1)
        self.assertEqual(nvd.merge([recent], [], at), [recent])
        self.assertEqual(nvd.merge([recent], [], at + timedelta(days=nvd.KEEP_DAYS + 1)), [])
        better = dict(recent, cvss=10.0)
        self.assertEqual(nvd.merge([recent], [better], at)[0]['cvss'], 10.0)

    def test_tally_counts_the_whole_answer(self):
        counts = nvd.tally(self.cves.values())
        self.assertEqual(counts['total'], 4)
        self.assertEqual(counts['critical'], 2)


class Travel(unittest.TestCase):
    def setUp(self):
        self.levels, self.items = state_rows()
        self.by = {r['country']: r for r in self.levels}

    def test_fips_tags_are_not_read_as_iso(self):
        self.assertEqual(self.by['Niger']['fips'], 'NG')
        self.assertEqual(self.by['Niger']['iso2'], 'NE')
        self.assertEqual(self.by['Togo']['iso2'], 'TG')

    def test_tonga_appears_once(self):
        self.assertEqual(sum(1 for r in self.levels if r['country'] == 'Tonga'), 1)

    def test_every_reason_style(self):
        self.assertEqual(self.by['Iran']['indicators'], ['T', 'U', 'K', 'D'])                 # bold words, "U.S." inside
        self.assertIn('wrongful detention', self.by['Iran']['reasons'])
        self.assertLessEqual({'C', 'K', 'T', 'U', 'H'}, set(self.by['Somalia']['indicators']))  # one bold list
        self.assertLessEqual({'U', 'C', 'K', 'T'}, set(self.by['Ethiopia']['indicators']))    # plain text
        self.assertLessEqual({'C', 'T', 'K'}, set(self.by['Mali']['indicators']))             # section headings only

    def test_dates_survive(self):
        self.assertEqual(self.by['Iran']['updated'], '2026-10-23')

    def test_level_four_for_security_reasons_is_severe(self):
        for country in ('Iran', 'Somalia', 'Mali', 'Gaza', 'Ukraine', 'Niger'):
            e = next(x for x in self.items if x['title'].startswith(country))
            self.assertEqual(e['severity'], events.SEVERE, country)

    def test_severity_rows(self):
        self.assertEqual(state.severity_of(4, ['landmines'], ['O']), events.MODERATE)
        self.assertEqual(state.severity_of(3, ['terrorism'], ['T']), events.MODERATE)
        self.assertEqual(state.severity_of(2, ['crime'], ['C']), events.MINOR)

    def test_a_war_is_a_conflict(self):
        self.assertEqual(next(x for x in self.items if x['title'].startswith('Ukraine'))['threat_class'], 'conflict')

    def test_arbitrary_enforcement_is_not_detention(self):
        self.assertEqual(state.indicators_of(['arbitrary enforcement of local laws']), ['O'])

    def test_level_one_has_no_event_but_keeps_its_row(self):
        self.assertIn('Bonaire', self.by)
        self.assertFalse(any(x['title'].startswith('Bonaire') for x in self.items))


class Gdacs(unittest.TestCase):
    def setUp(self):
        self.items, self.stats = gdacs.decode(load_json('gdacs.json'), NOW)
        self.kinds = {}
        for e in self.items:
            self.kinds.setdefault(e['kind'], []).append(e)

    def test_counts_cover_what_upstream_sent(self):
        self.assertEqual(self.stats['upstream_count'], 6)
        self.assertEqual(self.stats['current_count'], 1)

    def test_an_event_that_ended_long_ago_is_dropped(self):
        self.assertEqual(len(self.items), 5)
        self.assertNotIn('flood', self.kinds)

    def test_only_epicentres_and_vents_are_points(self):
        self.assertEqual(self.kinds['earthquake'][0]['geo_precision'], 'point')
        self.assertEqual(self.kinds['volcano'][0]['geo_precision'], 'point')

    def test_a_single_country_storm_gets_a_ring_and_a_shared_one_no_position(self):
        by_count = {len(e['countries']): e for e in self.kinds['cyclone']}
        self.assertEqual(by_count[1]['geo_precision'], 'country')
        shared = by_count[5]
        self.assertEqual(shared['geo_precision'], 'none')
        self.assertIsNone(shared['lat'])
        self.assertIsNone(shared['country_code'])

    def test_alert_levels(self):
        self.assertEqual(self.kinds['earthquake'][0]['severity'], events.SEVERE)
        self.assertEqual(self.kinds['volcano'][0]['severity'], events.MODERATE)
        self.assertTrue(all(e['threat_class'] == 'disruption' for e in self.items))


class Usgs(unittest.TestCase):
    def test_points(self):
        items = usgs.decode(load_json('usgs.json'))
        self.assertEqual(len(items), 2)
        self.assertTrue(all(e['geo_precision'] == 'point' and e['kind'] == 'earthquake' for e in items))

    def test_severity(self):
        self.assertEqual(usgs.severity_of(7.1, 'green', False), events.SEVERE)
        self.assertEqual(usgs.severity_of(5.2, 'orange', False), events.SEVERE)
        self.assertEqual(usgs.severity_of(6.1, None, False), events.MODERATE)
        self.assertEqual(usgs.severity_of(5.4, None, True), events.MODERATE)
        self.assertEqual(usgs.severity_of(5.4, 'green', False), events.MINOR)


class Conductor(unittest.TestCase):
    def setUp(self):
        conductor.status['feeds'] = {'a': {'last_start_ts': 1000.0}}

    def test_a_tick_that_lands_a_little_early_still_counts(self):
        spec = {'every': 3600}
        self.assertTrue(conductor.due('a', spec, 1000 + 3600 - conductor.SLACK))
        self.assertFalse(conductor.due('a', spec, 1000 + 600))

    def test_a_feed_never_run_is_due(self):
        self.assertTrue(conductor.due('new', {'every': 3600}, NOW.timestamp()))

    def test_the_registry_is_complete(self):
        for name, spec in conductor.FEEDS.items():
            self.assertLessEqual({'code', 'run', 'every', 'timeout'}, set(spec), name)
            for folder in spec['code']:
                self.assertTrue(os.path.isdir(os.path.join(FEEDS, folder)), folder)
            for cmd in spec['run']:
                self.assertTrue(any(os.path.isfile(os.path.join(FEEDS, c, cmd[1])) for c in spec['code']), cmd[1])


if __name__ == '__main__':
    unittest.main()
