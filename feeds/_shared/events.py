"""The ThreatEvent record and the rules every feed shares.

threat_class  terrorism | unrest | conflict | cyber | disruption | crime | unknown
kind          one slug per event; the feeds in this repo use KINDS below
severity      0 INFO · 1 MINOR · 2 MODERATE · 3 SEVERE · 4 EXTREME
source_tier   official | aggregator | news
geo_precision point | admin1 | country | none
url           provenance only; clients never render it as a link
"""
from tf import iso, iso_week, parse_date, stable_id
import geocode

CLASSES = ('terrorism', 'unrest', 'conflict', 'cyber', 'disruption', 'crime', 'unknown')
KINDS = ('kevAddition', 'cyberAdvisory', 'advisory', 'earthquake', 'cyclone', 'flood', 'volcano', 'drought', 'wildfire',
         # unrest and violence from GDELT Events 2.0 (feed gdeltevents): CAMEO 14 protest · 17 coerce · 18 assault · 19 fight · 20 mass violence
         'protest', 'hungerStrike', 'strike', 'blockade', 'riot', 'crackdown', 'curfew', 'massArrest', 'expulsion', 'repression',
         'abduction', 'assault', 'bombing', 'assassination', 'armedClash', 'artillery', 'airstrike', 'ceasefireViolation', 'massViolence', 'massKilling')
TIERS = ('official', 'aggregator', 'news')
PRECISION = ('point', 'admin1', 'country', 'none')
INFO, MINOR, MODERATE, SEVERE, EXTREME = 0, 1, 2, 3, 4
SEVERITY_LABEL = ['INFO', 'MINOR', 'MODERATE', 'SEVERE', 'EXTREME']


def _when(value):
    return iso(value) if value is not None and not isinstance(value, str) else value


def make(*, source, source_tier, kind, threat_class, title, updated, severity=INFO, headline=None, body=None,
         instruction=None, target_sector=None, area=None, country_code=None, countries=None, lat=None, lng=None,
         cve_ids=None, cvss=None, kev=None, known_ransomware_use=None, products=None, onset=None, expires=None,
         url=None, facts=None, credit=None, licence=None, tags=None, source_id=None) -> dict:
    """One ThreatEvent. A given lat/lng is a true point; otherwise a named country gives its centroid and a
    ring of half the country's diagonal, and an event spanning several countries carries no position at all."""
    assert kind in KINDS, kind
    assert threat_class in CLASSES, threat_class
    assert source_tier in TIERS, source_tier
    place = geocode.country(country_code) if country_code else None
    if lat is not None:
        precision, radius = 'point', 0.0
    elif place:
        lat, lng = place['lat'], place['lng']
        precision, radius = 'country', geocode.radius_km(place.get('bbox'))
    else:
        precision, radius = 'none', None
    if area is None and place:
        area = place['name']
    return {
        'id': stable_id(source, source_id or url or title),
        'kind': kind,
        'threat_class': threat_class,
        'severity': int(severity),
        'severity_label': SEVERITY_LABEL[int(severity)],
        'source': source,
        'source_tier': source_tier,
        'title': title,
        'headline': headline,
        'body': body,
        'instruction': instruction,
        'actor': None,
        'actor_name': None,
        'actor_type': None,
        'target_sector': target_sector,
        'target_type': None,
        'area': area,
        'country_code': country_code,
        'countries': countries or ([country_code] if country_code else []),
        'admin1': None,
        'admin1_code': None,
        'lat': lat,
        'lng': lng,
        'geo_precision': precision,
        'geo_radius_km': radius,
        'region': geocode.area_of(country_code, lng) if country_code else 'global',
        'fatalities': None,
        'injuries': None,
        'casualties_quote': None,
        'records': None,
        'cve_ids': cve_ids or [],
        'cvss': cvss,
        'epss': None,
        'kev': kev,
        'known_ransomware_use': known_ransomware_use,
        'products': products or [],
        'onset': _when(onset),
        'updated': _when(updated),
        'expires': _when(expires),
        'url': url,
        'facts': facts or [],
        'credit': credit,
        'licence': licence,
        'tags': tags or [],
        'corroboration': 0,
        'cluster': f'{threat_class}|{country_code or ""}||{iso_week(parse_date(_when(onset) or _when(updated)))}',
    }
