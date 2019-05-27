import json
from helios.models import *
from django.conf import settings
from zeus.utils import CSVReader
from collections import defaultdict


ELECTIONS = []
INSTITUTIONS = []

SMART_MAP = getattr(settings, 'ZEUS_ELECTION_STATS_SMART_MAP', True)
INSTITUTION_MAP_PATH = getattr(settings, 'ZEUS_ELECTION_STATS_INSTITUTION_MAP_PATH', None)

INSTITUTIONS = []
BASE_INSTITUTIONS = []
INSTITUTION_MAP = {}

def setup_institutions(entries):
    if INSTITUTION_MAP_PATH:
        with open(INSTITUTION_MAP_PATH) as fd:
            INSTITUTION_MAP.update(json.load(fd))

    for name, user in entries:
        inst = name
        if inst in INSTITUTION_MAP:
            inst = INSTITUTION_MAP[inst]
        if '-' in name and SMART_MAP:
            inst = name.split("-")[0]
        if inst in INSTITUTION_MAP:
            inst = INSTITUTION_MAP[inst]
        
        INSTITUTION_MAP[inst] = inst
        return inst
        

def get_institution(name):
    return INSTITUTION_MAP[name]


def elections_from_csv(sort_keys=['polls', 'voters']):
    db = {
        'turnout': -1,
        'elections_count': 0,
        'polls_count': 0,
        'voters_count': 0,
        'elections_held': {},
        'institutions_sorted': [],
        'institutions': defaultdict(lambda: dict(name=None, elections=0, polls=0, voters=0, voted=0))
    }
    
    csv_path = getattr(settings, 'ZEUS_ELECTION_STATS_CSV_PATH', None)
    if not csv_path:
        return db

    csvdata = ''
    with open(csv_path) as fd:
        csvdata = fd.read()

    csv = CSVReader(csvdata, max_fields=10, min_fields=5)
    insts = []
    for row in csv:
        if not row[0]:
            continue
        insts.append([row[0], row[-1]])
    setup_institutions(insts)

    csv = CSVReader(csvdata, max_fields=10, min_fields=5)
    election = {}
    
    for row in csv:
        if not row[0]:
            continue
        election['institution'] = get_institution(row[0])
        try:
            int(row[1])
        except ValueError:
            continue
        election['voters'] = int(row[1])
        election['voted'] = int(row[2])
        election['turnout'] = float(election['voters']) / float(election['voted'])
        election['start_at'] = row[3]
        election['end_at'] = row[4]
        election['id'] = row[5]
        election['name'] = row[6]
        election['user'] = row[7]
        election['index'] = election['institution'] + election['end_at'] + election['start_at']
        INSTITUTIONS.append(election['institution'])
        if db['turnout'] == -1:
            db['turnout'] = election['turnout']
        db['turnout'] = (db['turnout'] + election['turnout']) / 2
        inst = db['institutions'][election['institution']]
        if election['index'] not in ELECTIONS:
            inst['elections'] += 1
        inst['polls'] += 1
        inst['voters'] += election['voters']
        inst['name'] = election['institution']

        db['polls_count'] += 1
        db['voters_count'] += election['voters']
        ELECTIONS.append(election['index'])

    db['elections_count'] = len(set(ELECTIONS))
    db['institutions_count'] = len(set(INSTITUTIONS))
    db['institutions'] = dict(db['institutions'])
    def cmp(a, b):
        result = 0
        for key in sort_keys:
            val1 = a[key]
            valb = b[key]
            if val1 == valb:
                continue
            result = -1 if val1 > valb else 1
            break
        return result
    
    db['institutions_sorted'] = sorted(db['institutions'].values(), cmp=cmp)
    return db
