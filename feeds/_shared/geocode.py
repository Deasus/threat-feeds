"""Country / state geocoding for the pipeline (no network).

Natural Earth centroids come from centroids.py (generated). This module adds the
long-form and colloquial names that governments, aggregators and
news use, an ISO3 → ISO2 table (several aggregators speak ISO3), US state names, and
an area classification so the app can filter by the user's area without
re-deriving it.

find_countries(text) matches longest names first on word boundaries. A handful of
ambiguous names (Georgia, Jordan, Chad, Niger vs Nigeria is handled by boundaries)
are guarded; corroboration downstream catches the rest.
"""
import re
from centroids import COUNTRIES, STATES

_C = {}          # iso2 -> dict
# Natural Earth lists some disputed/unrecognised territories under their parent's ISO code; they must not
# overwrite the parent (Somaliland came after Somalia and took 'SO').
_SHADOWED = {'Somaliland', 'N. Cyprus', 'Siachen Glacier', 'Indian Ocean Ter.'}
for name, iso2, continent, subregion, lat, lng, bb in COUNTRIES:
    if name in _SHADOWED and iso2 in _C:
        continue
    if name in _SHADOWED:
        continue
    _C[iso2] = {'name': name, 'iso2': iso2, 'continent': continent, 'subregion': subregion,
                'lat': lat, 'lng': lng, 'bbox': bb}
_C['US']['name'] = 'United States'
# Places missing from the Natural Earth country list (overseas departments and territories) with their own centroids,
# so a notice for Mayotte is not drawn in Paris.
for name, iso2, continent, subregion, lat, lng in [
    ('French Guiana', 'GF', 'South America', 'South America', 3.9, -53.1), ('Mayotte', 'YT', 'Africa', 'Eastern Africa', -12.8, 45.2),
    ('Réunion', 'RE', 'Africa', 'Eastern Africa', -21.1, 55.5), ('Guadeloupe', 'GP', 'North America', 'Caribbean', 16.2, -61.5),
    ('Martinique', 'MQ', 'North America', 'Caribbean', 14.6, -61.0), ('Gibraltar', 'GI', 'Europe', 'Southern Europe', 36.14, -5.35),
    ('Tokelau', 'TK', 'Oceania', 'Polynesia', -9.2, -171.8), ('Svalbard', 'SJ', 'Europe', 'Northern Europe', 78.0, 16.0),
]:
    _C.setdefault(iso2, {'name': name, 'iso2': iso2, 'continent': continent, 'subregion': subregion, 'lat': lat, 'lng': lng, 'bbox': None})

ALIASES = {
    'united states': 'US', 'united states of america': 'US', 'usa': 'US', 'u.s.': 'US', 'u.s.a.': 'US', 'the united states': 'US',
    'united kingdom': 'GB', 'uk': 'GB', 'u.k.': 'GB', 'britain': 'GB', 'great britain': 'GB', 'england': 'GB', 'scotland': 'GB', 'wales': 'GB',
    'northern ireland': 'GB', 'united kingdom of great britain and northern ireland': 'GB',
    'democratic republic of the congo': 'CD', 'the democratic republic of the congo': 'CD', 'democratic republic of congo': 'CD',
    'dr congo': 'CD', 'drc': 'CD', 'congo, dem. rep.': 'CD', 'congo (kinshasa)': 'CD', 'congo-kinshasa': 'CD', 'congo': 'CD',
    'republic of the congo': 'CG', 'republic of congo': 'CG', 'congo-brazzaville': 'CG', 'congo (brazzaville)': 'CG',
    'ivory coast': 'CI', "cote d'ivoire": 'CI', 'cote divoire': 'CI', "côte d'ivoire": 'CI', 'côte d’ivoire': 'CI', "cote d’ivoire": 'CI',
    'tanzania': 'TZ', 'united republic of tanzania': 'TZ', 'zanzibar': 'TZ',
    'russian federation': 'RU', 'viet nam': 'VN', "lao people's democratic republic": 'LA', 'lao pdr': 'LA', 'laos': 'LA',
    'iran (islamic republic of)': 'IR', 'islamic republic of iran': 'IR', 'syrian arab republic': 'SY',
    'bolivia (plurinational state of)': 'BO', 'plurinational state of bolivia': 'BO',
    'venezuela (bolivarian republic of)': 'VE', 'bolivarian republic of venezuela': 'VE',
    'republic of korea': 'KR', 'korea, republic of': 'KR', 'south korea': 'KR',
    "democratic people's republic of korea": 'KP', 'dprk': 'KP', 'north korea': 'KP',
    'czech republic': 'CZ', 'burma': 'MM', 'myanmar (burma)': 'MM', 'swaziland': 'SZ', 'eswatini': 'SZ', 'kingdom of eswatini': 'SZ',
    'macedonia': 'MK', 'republic of north macedonia': 'MK',
    'occupied palestinian territory': 'PS', 'palestinian territories': 'PS', 'state of palestine': 'PS', 'west bank': 'PS', 'gaza': 'PS', 'gaza strip': 'PS',
    'hong kong sar': 'HK', 'hong kong special administrative region': 'HK', 'macao sar': 'MO', 'macau': 'MO',
    'taiwan, china': 'TW', 'chinese taipei': 'TW', "people's republic of china": 'CN', 'mainland china': 'CN', 'prc': 'CN', 'tibet': 'CN',
    'kingdom of saudi arabia': 'SA', 'ksa': 'SA', 'türkiye': 'TR', 'turkiye': 'TR', 'republic of türkiye': 'TR',
    'the netherlands': 'NL', 'holland': 'NL', 'the gambia': 'GM', 'the bahamas': 'BS', 'cape verde': 'CV', 'cabo verde': 'CV',
    'east timor': 'TL', 'timor leste': 'TL', 'south sudan': 'SS', 'republic of south sudan': 'SS', 'the sudan': 'SD',
    'central african republic': 'CF', 'equatorial guinea': 'GQ', 'dominican republic': 'DO',
    'bosnia and herzegovina': 'BA', 'bosnia': 'BA', 'western sahara': 'EH', 'solomon islands': 'SB', 'marshall islands': 'MH',
    'french polynesia': 'PF', 'antigua and barbuda': 'AG', 'saint kitts and nevis': 'KN', 'st. kitts and nevis': 'KN', 'st kitts and nevis': 'KN',
    'saint vincent and the grenadines': 'VC', 'st. vincent and the grenadines': 'VC', 'saint lucia': 'LC', 'trinidad': 'TT',
    'cayman islands': 'KY', 'british virgin islands': 'VG', 'us virgin islands': 'VI', 'u.s. virgin islands': 'VI', 'virgin islands': 'VI',
    'northern mariana islands': 'MP', 'commonwealth of northern mariana islands': 'MP', 'cook islands': 'CK', 'faroe islands': 'FO',
    'falkland islands': 'FK', 'turks and caicos': 'TC', 'turks and caicos islands': 'TC',
    'são tomé and príncipe': 'ST', 'sao tome and principe': 'ST', 'sao tome': 'ST', 'são tomé': 'ST',
    'brunei darussalam': 'BN', 'republic of moldova': 'MD', 'moldova, republic of': 'MD',
    'micronesia (federated states of)': 'FM', 'federated states of micronesia': 'FM', 'guinea bissau': 'GW',
    'uae': 'AE', 'the philippines': 'PH', 'kyrgyz republic': 'KG', 'slovak republic': 'SK', 'yemen, rep.': 'YE', 'egypt, arab rep.': 'EG',
    'wallis and futuna': 'WF', 'saint martin': 'MF', 'saint barthelemy': 'BL', 'saint pierre and miquelon': 'PM',
    'kosovo': 'XK', 'new caledonia': 'NC', 'puerto rico': 'PR', 'guam': 'GU', 'american samoa': 'AS',
    'nagorno-karabakh': 'AZ', 'somaliland': 'SO',
    'reunion': 'RE', 'la réunion': 'RE', 'la reunion': 'RE',
}

# The State Department's RSS "Country-Tag" is FIPS 10-4, not ISO 3166 (China is CH, Switzerland SZ, Germany GM,
# Japan JA, the UK UK…). Only the codes that differ from ISO are listed; identical ones pass through.
FIPS_TO_ISO = {
    'AA': 'AW', 'AC': 'AG', 'AG': 'DZ', 'AJ': 'AZ', 'AN': 'AD', 'AQ': 'AS', 'AS': 'AU', 'AU': 'AT', 'AV': 'AI', 'AY': 'AQ',
    'BA': 'BH', 'BC': 'BW', 'BD': 'BM', 'BF': 'BS', 'BG': 'BD', 'BH': 'BZ', 'BK': 'BA', 'BL': 'BO', 'BM': 'MM', 'BN': 'BJ',
    'BO': 'BY', 'BP': 'SB', 'BU': 'BG', 'BX': 'BN', 'CB': 'KH', 'CD': 'TD', 'CE': 'LK', 'CF': 'CG', 'CG': 'CD', 'CH': 'CN',
    'CI': 'CL', 'CJ': 'KY', 'CK': 'CC', 'CN': 'KM', 'CQ': 'MP', 'CS': 'CR', 'CT': 'CF', 'CW': 'CK', 'DA': 'DK', 'DO': 'DM',
    'DR': 'DO', 'EI': 'IE', 'EK': 'GQ', 'EN': 'EE', 'ES': 'SV', 'EZ': 'CZ', 'FG': 'GF', 'FP': 'PF', 'GA': 'GM', 'GB': 'GA',
    'GG': 'GE', 'GJ': 'GD', 'GK': 'GG', 'GM': 'DE', 'GQ': 'GU', 'GV': 'GN', 'HA': 'HT', 'HO': 'HN', 'IC': 'IS', 'IS': 'IL',
    'IV': 'CI', 'IZ': 'IQ', 'JA': 'JP', 'KN': 'KP', 'KR': 'KI', 'KS': 'KR', 'KU': 'KW', 'KV': 'XK', 'LE': 'LB', 'LG': 'LV',
    'LH': 'LT', 'LI': 'LR', 'LO': 'SK', 'LS': 'LI', 'MA': 'MG', 'MB': 'MQ', 'MC': 'MO', 'MF': 'YT', 'MG': 'MN', 'MH': 'MS',
    'MI': 'MW', 'MJ': 'ME', 'MN': 'MC', 'MO': 'MA', 'MP': 'MU', 'MU': 'OM', 'NG': 'NE', 'NH': 'VU', 'NI': 'NG', 'NN': 'SX',
    'NS': 'SR', 'NU': 'NI', 'PA': 'PY', 'PC': 'PN', 'PM': 'PA', 'PO': 'PT', 'PP': 'PG', 'PS': 'PW', 'PU': 'GW', 'RB': 'RS',
    'RM': 'MH', 'RP': 'PH', 'RQ': 'PR', 'RS': 'RU', 'SB': 'PM', 'SC': 'KN', 'SE': 'SC', 'SF': 'ZA', 'SG': 'SN', 'SN': 'SG',
    'SP': 'ES', 'ST': 'LC', 'SU': 'SD', 'SW': 'SE', 'SZ': 'CH', 'TB': 'BL', 'TD': 'TT', 'TI': 'TJ', 'TK': 'TC', 'TL': 'TK',
    'TN': 'TO', 'TO': 'TG', 'TP': 'ST', 'TS': 'TN', 'TT': 'TL', 'TU': 'TR', 'TX': 'TM', 'UK': 'GB', 'UP': 'UA', 'VI': 'VG',
    'VM': 'VN', 'VQ': 'VI', 'WA': 'NA', 'WE': 'PS', 'WI': 'EH', 'WZ': 'SZ', 'ZA': 'ZM', 'ZI': 'ZW',
}


def country_from_fips(code: str):
    if not code:
        return None
    c = code.strip().upper()
    return country(FIPS_TO_ISO.get(c, c))


ISO3 = {
    'AFG': 'AF', 'ALB': 'AL', 'DZA': 'DZ', 'ASM': 'AS', 'AND': 'AD', 'AGO': 'AO', 'AIA': 'AI', 'ATA': 'AQ', 'ATG': 'AG', 'ARG': 'AR', 'ARM': 'AM',
    'ABW': 'AW', 'AUS': 'AU', 'AUT': 'AT', 'AZE': 'AZ', 'BHS': 'BS', 'BHR': 'BH', 'BGD': 'BD', 'BRB': 'BB', 'BLR': 'BY', 'BEL': 'BE', 'BLZ': 'BZ',
    'BEN': 'BJ', 'BMU': 'BM', 'BTN': 'BT', 'BOL': 'BO', 'BIH': 'BA', 'BWA': 'BW', 'BRA': 'BR', 'IOT': 'IO', 'VGB': 'VG', 'BRN': 'BN', 'BGR': 'BG',
    'BFA': 'BF', 'BDI': 'BI', 'CPV': 'CV', 'KHM': 'KH', 'CMR': 'CM', 'CAN': 'CA', 'CYM': 'KY', 'CAF': 'CF', 'TCD': 'TD', 'CHL': 'CL', 'CHN': 'CN',
    'COL': 'CO', 'COM': 'KM', 'COG': 'CG', 'COD': 'CD', 'COK': 'CK', 'CRI': 'CR', 'CIV': 'CI', 'HRV': 'HR', 'CUB': 'CU', 'CUW': 'CW', 'CYP': 'CY',
    'CZE': 'CZ', 'DNK': 'DK', 'DJI': 'DJ', 'DMA': 'DM', 'DOM': 'DO', 'ECU': 'EC', 'EGY': 'EG', 'SLV': 'SV', 'GNQ': 'GQ', 'ERI': 'ER', 'EST': 'EE',
    'SWZ': 'SZ', 'ETH': 'ET', 'FLK': 'FK', 'FRO': 'FO', 'FJI': 'FJ', 'FIN': 'FI', 'FRA': 'FR', 'GUF': 'GF', 'PYF': 'PF', 'GAB': 'GA', 'GMB': 'GM',
    'GEO': 'GE', 'DEU': 'DE', 'GHA': 'GH', 'GIB': 'GI', 'GRC': 'GR', 'GRL': 'GL', 'GRD': 'GD', 'GLP': 'GP', 'GUM': 'GU', 'GTM': 'GT', 'GGY': 'GG',
    'GIN': 'GN', 'GNB': 'GW', 'GUY': 'GY', 'HTI': 'HT', 'HND': 'HN', 'HKG': 'HK', 'HUN': 'HU', 'ISL': 'IS', 'IND': 'IN', 'IDN': 'ID', 'IRN': 'IR',
    'IRQ': 'IQ', 'IRL': 'IE', 'IMN': 'IM', 'ISR': 'IL', 'ITA': 'IT', 'JAM': 'JM', 'JPN': 'JP', 'JEY': 'JE', 'JOR': 'JO', 'KAZ': 'KZ', 'KEN': 'KE',
    'KIR': 'KI', 'PRK': 'KP', 'KOR': 'KR', 'XKX': 'XK', 'KWT': 'KW', 'KGZ': 'KG', 'LAO': 'LA', 'LVA': 'LV', 'LBN': 'LB', 'LSO': 'LS', 'LBR': 'LR',
    'LBY': 'LY', 'LIE': 'LI', 'LTU': 'LT', 'LUX': 'LU', 'MAC': 'MO', 'MDG': 'MG', 'MWI': 'MW', 'MYS': 'MY', 'MDV': 'MV', 'MLI': 'ML', 'MLT': 'MT',
    'MHL': 'MH', 'MTQ': 'MQ', 'MRT': 'MR', 'MUS': 'MU', 'MYT': 'YT', 'MEX': 'MX', 'FSM': 'FM', 'MDA': 'MD', 'MCO': 'MC', 'MNG': 'MN', 'MNE': 'ME',
    'MSR': 'MS', 'MAR': 'MA', 'MOZ': 'MZ', 'MMR': 'MM', 'NAM': 'NA', 'NRU': 'NR', 'NPL': 'NP', 'NLD': 'NL', 'NCL': 'NC', 'NZL': 'NZ', 'NIC': 'NI',
    'NER': 'NE', 'NGA': 'NG', 'NIU': 'NU', 'NFK': 'NF', 'MKD': 'MK', 'MNP': 'MP', 'NOR': 'NO', 'OMN': 'OM', 'PAK': 'PK', 'PLW': 'PW', 'PSE': 'PS',
    'PAN': 'PA', 'PNG': 'PG', 'PRY': 'PY', 'PER': 'PE', 'PHL': 'PH', 'PCN': 'PN', 'POL': 'PL', 'PRT': 'PT', 'PRI': 'PR', 'QAT': 'QA', 'REU': 'RE',
    'ROU': 'RO', 'RUS': 'RU', 'RWA': 'RW', 'BLM': 'BL', 'SHN': 'SH', 'KNA': 'KN', 'LCA': 'LC', 'MAF': 'MF', 'SPM': 'PM', 'VCT': 'VC', 'WSM': 'WS',
    'SMR': 'SM', 'STP': 'ST', 'SAU': 'SA', 'SEN': 'SN', 'SRB': 'RS', 'SYC': 'SC', 'SLE': 'SL', 'SGP': 'SG', 'SXM': 'SX', 'SVK': 'SK', 'SVN': 'SI',
    'SLB': 'SB', 'SOM': 'SO', 'ZAF': 'ZA', 'SGS': 'GS', 'SSD': 'SS', 'ESP': 'ES', 'LKA': 'LK', 'SDN': 'SD', 'SUR': 'SR', 'SWE': 'SE', 'CHE': 'CH',
    'SYR': 'SY', 'TWN': 'TW', 'TJK': 'TJ', 'TZA': 'TZ', 'THA': 'TH', 'TLS': 'TL', 'TGO': 'TG', 'TKL': 'TK', 'TON': 'TO', 'TTO': 'TT', 'TUN': 'TN',
    'TUR': 'TR', 'TKM': 'TM', 'TCA': 'TC', 'TUV': 'TV', 'UGA': 'UG', 'UKR': 'UA', 'ARE': 'AE', 'GBR': 'GB', 'USA': 'US', 'URY': 'UY', 'UZB': 'UZ',
    'VUT': 'VU', 'VEN': 'VE', 'VNM': 'VN', 'VIR': 'VI', 'WLF': 'WF', 'ESH': 'EH', 'YEM': 'YE', 'ZMB': 'ZM', 'ZWE': 'ZW', 'ALA': 'AX',
    'WLD': None, 'ROW': None,
}

# Names too short or too ambiguous to match on their own in free text.
_SKIP_NAMES = {'Chad', 'Jordan', 'Georgia', 'Guinea', 'Niger', 'Congo', 'Palestine', 'Micronesia', 'Macao', 'Åland', 'Siachen Glacier',
               'Indian Ocean Ter.', 'Br. Indian Ocean Ter.', 'Heard I. and McDonald Is.', 'Fr. S. Antarctic Lands', 'S. Geo. and the Is.',
               'N. Cyprus', 'Antarctica', 'Somaliland'}
_GUARDED = {'Chad': 'TD', 'Jordan': 'JO', 'Georgia': 'GE', 'Guinea': 'GN', 'Niger': 'NE'}


def _patterns():
    pats = []
    for iso2, c in _C.items():
        if c['name'] not in _SKIP_NAMES:
            pats.append((c['name'], iso2))
    for alias, iso2 in ALIASES.items():
        pats.append((alias, iso2))
    pats.sort(key=lambda p: -len(p[0]))
    rx = re.compile(r'(?<![\w])(' + '|'.join(re.escape(n) for n, _ in pats) + r')(?![\w])', re.I)
    lookup = {n.lower(): iso2 for n, iso2 in pats}
    return rx, lookup


_RX, _LOOKUP = _patterns()
_GUARD_RX = re.compile(r'\b(' + '|'.join(_GUARDED) + r')\b')
_US_CONTEXT = re.compile(r'\b(atlanta|savannah|cdc|u\.s\.|united states|georgia department|georgia dph|gdph)\b', re.I)


def country(code_or_name: str):
    """A country by ISO2, ISO3 or name/alias → {name, iso2, lat, lng, continent, subregion, bbox} or None."""
    if not code_or_name:
        return None
    q = code_or_name.strip()
    if len(q) == 2 and q.upper() in _C:
        return _C[q.upper()]
    if len(q) == 3 and q.upper() in ISO3:
        iso2 = ISO3[q.upper()]
        return _C.get(iso2) if iso2 else None
    iso2 = _LOOKUP.get(q.lower())
    if iso2 is None:
        for c in _C.values():
            if c['name'].lower() == q.lower():
                return c
        return None
    return _C.get(iso2)


def find_countries(text: str) -> list:
    """Countries named in text, in order of first appearance, de-duplicated."""
    if not text:
        return []
    found = []
    for m in _RX.finditer(text):
        iso2 = _LOOKUP.get(m.group(1).lower())
        if iso2 and iso2 in _C:
            found.append((m.start(), iso2))
    for m in _GUARD_RX.finditer(text):
        name = m.group(1)
        if name == 'Georgia' and _US_CONTEXT.search(text):
            continue
        if name == 'Guinea' and re.search(r'guinea[- ]?(bissau|pig|worm)|new guinea|equatorial guinea', text, re.I):
            continue
        if name == 'Niger' and re.search(r'nigeria', text[m.start():m.start() + 8], re.I):
            continue
        if name in ('Chad', 'Jordan') and re.search(name + r"\s+[A-Z][a-z]+", text):      # a person's name
            continue
        found.append((m.start(), _GUARDED[name]))
    seen, out = set(), []
    for _, iso2 in sorted(found):
        if iso2 not in seen:
            seen.add(iso2)
            out.append(_C[iso2])
    return out


def radius_km(bbox):
    """Half the diagonal of a [minLng, minLat, maxLng, maxLat] box, in km: how far a centroid may be from the truth."""
    if not bbox:
        return None
    import math
    min_lng, min_lat, max_lng, max_lat = bbox
    mid_lat = math.radians((min_lat + max_lat) / 2)
    dx = (max_lng - min_lng) * 111.32 * math.cos(mid_lat)
    dy = (max_lat - min_lat) * 110.57
    return round(min(math.hypot(dx, dy) / 2, 2500), 0)


def area_of(iso2: str, lng=None) -> str:
    """The coarse map area a country belongs to."""
    c = _C.get(iso2)
    if not c:
        return 'global'
    if iso2 == 'US':
        return 'unitedStates'
    if iso2 == 'CA':
        return 'canada'
    if iso2 == 'RU':
        return 'europe' if (lng if lng is not None else c['lng']) < 60 else 'asia'
    if iso2 == 'GL':
        return 'europe'
    cont, sub = c['continent'], c['subregion']
    if cont in ('North America', 'South America'):
        return 'latinAmerica'
    if cont == 'Europe':
        return 'europe'
    if cont == 'Africa':
        return 'africa'
    if cont == 'Asia':
        return 'middleEast' if sub == 'Western Asia' else 'asia'
    if cont == 'Oceania':
        return 'oceania'
    return 'global'


# ── US / CA / AU states and provinces ──────────────────────────────────────────

_STATES = {}
for name, code, k, lat, lng, bb in STATES:
    _STATES[(k, code)] = {'name': name, 'code': code, 'country': k, 'lat': lat, 'lng': lng, 'bbox': bb}
_STATE_BY_NAME = {(k, s['name'].lower()): s for (k, _), s in _STATES.items()}
_STATE_BY_NAME[('US', 'washington, d.c.')] = _STATES.get(('US', 'DC'))
_STATE_BY_NAME[('US', 'washington dc')] = _STATES.get(('US', 'DC'))
_STATE_BY_NAME[('US', 'new york city')] = _STATES.get(('US', 'NY'))
_US_RX = re.compile(r'(?<![\w])(' + '|'.join(sorted((re.escape(n) for (k, n) in _STATE_BY_NAME if k == 'US'), key=len, reverse=True)) + r')(?![\w])', re.I)


def state(code_or_name: str, country_iso2: str = 'US'):
    if not code_or_name:
        return None
    q = code_or_name.strip()
    s = _STATES.get((country_iso2, q.upper()))
    if s:
        return s
    return _STATE_BY_NAME.get((country_iso2, q.lower()))


def find_us_states(text: str) -> list:
    out, seen = [], set()
    for m in _US_RX.finditer(text or ''):
        s = _STATE_BY_NAME.get(('US', m.group(1).lower()))
        if s and s['code'] not in seen:
            seen.add(s['code'])
            out.append(s)
    return out


def distance_km(a, b) -> float:
    """Great-circle distance between (lat, lng) pairs, in km."""
    import math
    la1, lo1, la2, lo2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(h))
