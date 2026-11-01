# threat-feeds

Scheduled mirrors of public cyber-security, travel-advisory and natural-hazard feeds, normalised to one event
schema and served from `raw.githubusercontent.com`. Clients read JSON here instead of hitting the upstream
sources, which are rate-limited (NVD), slow, or closed to datacentre clients (cisa.gov's RSS).

One scheduled GitHub Actions job (`conductor.py`) runs each hour, runs whichever feeds are due and exits. Each feed
publishes its `data/` directory as a single-commit branch, so the repository never accumulates data history.

```
https://raw.githubusercontent.com/Deasus/threat-feeds/<feed>/<file>
https://raw.githubusercontent.com/Deasus/threat-feeds/status/status.json    # health of every feed
https://raw.githubusercontent.com/Deasus/threat-feeds/<feed>/checked.json   # the feed's last fully good cycle
```

## Feeds

| Branch | File | Upstream | Licence |
|---|---|---|---|
| `cisa` | `kev.json` | CISA Known Exploited Vulnerabilities: `catalog` holds every entry, `items` the additions of the last 45 days | CC0 1.0; no CISA logo |
| `cisa` | `ics.json` | CISA ICS advisories from CISA's CSAF feed on `cisagov/CSAF`, last 45 days | US Government work, public domain; CISA notification terms; no CISA logo |
| `vulns` | `critical.json` | NVD CVE API 2.0: `rows` holds CVEs published in the last 30 days with CVSS ≥ 9. A side table; `items` stays empty | US Government work. This product uses data from the NVD API but is not endorsed or certified by the NVD. |
| `travel` | `advisories.json` | US State Department travel advisories: `levels` holds every destination, `items` those at Level 2 or above | US Government work, public domain |
| `hazards` | `gdacs.json` | GDACS Orange and Red alerts, events that ended in the last 45 days | GDACS terms of use; European Commission reuse notice |
| `hazards` | `quakes.json` | USGS significant earthquakes, past 7 days | US Government work, public domain. Credit: U.S. Geological Survey |

GDACS notifications are automatic estimates that may contain errors. They do not replace alerts from local or
national authorities and need confirming before any decision; `gdacs.json` carries that notice.

## Files

Every event file is an envelope: `generated_at`, `upstream`, `credit`, `licence`, `count`, feed-specific fields,
then `items`, a list of events with the same fields:

```
id, kind, threat_class, severity (0–4), severity_label, source, source_tier, title, headline, body, instruction,
actor, actor_name, actor_type, target_sector, target_type, area, country_code, countries[], admin1, admin1_code,
lat, lng, geo_precision (point | admin1 | country | none), geo_radius_km, region, fatalities, injuries,
casualties_quote, records, cve_ids[], cvss, epss, kev, known_ransomware_use, products[], onset, updated, expires,
url, facts [[label, value]], credit, licence, tags[], corroboration, cluster
```

`url` is provenance. A position is never finer than the source gives: an event known only by country carries the
country's centroid and a ring (`geo_radius_km`), and one spanning several countries carries `countries[]` and no
position.

## Running it

Python 3.9+, standard library only.

```
python3 -m unittest discover -s tests -q                     # decoders on fixtures; no network
CONDUCTOR_PUSH=0 CONDUCTOR_ONLY=travel python3 conductor.py  # one feed, due or not, nothing pushed
```

A failed fetch keeps the last good file, marks the feed failed in `status.json` and fails the run.
Run fetchers locally to test them, rather than dispatching the workflow.
