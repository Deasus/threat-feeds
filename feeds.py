"""Feed registry for conductor.py.

Each feed's output lives on a branch of the same name; the branch root is the
feed's data/ directory, so a file is served at
  https://raw.githubusercontent.com/Deasus/threat-feeds/<feed>/<path>

every     target seconds between run starts (the schedule ticks hourly, so nothing runs faster)
timeout   seconds allowed per command
run       commands, run in order inside work/<feed>/
code      feeds/<dir>/ folders copied into the work dir (files land side by side; _shared holds the helpers)
requires  env vars that must be set, else the feed is skipped (shown in status.json)
keep_going run every command even if one fails
ignore    patterns under data/ never published

Cadences follow the upstream rhythm: CISA several a day, NVD continuous (5 requests per 30 s
without a key), State Department per advisory, GDACS and USGS continuous.
"""

FEEDS = {
    'cisa':    {'code': ['cisa', '_shared'], 'keep_going': True,
                'run': [['python3', 'fetch_kev.py'], ['python3', 'fetch_ics.py']],
                'every': 3600, 'timeout': 300},
    'vulns':   {'code': ['vulns', '_shared'], 'run': [['python3', 'fetch_nvd.py']],
                'every': 3600, 'timeout': 420},
    'travel':  {'code': ['travel', '_shared'], 'run': [['python3', 'fetch_state.py']],
                'every': 3600, 'timeout': 180},
    'hazards': {'code': ['hazards', '_shared'], 'keep_going': True,
                'run': [['python3', 'fetch_gdacs.py'], ['python3', 'fetch_usgs.py']],
                'every': 3600, 'timeout': 180},
}
