import sys, os, json, time, importlib
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, HERE)
import numpy as np
import core
from core import PROTOCOL, TRAIN_FRAC, WIN, DETECTORS

def main(dataset, root, outdir=None):
    t_all = time.time()
    ad = importlib.import_module('adapters.' + dataset.lower()).Adapter()
    out = outdir or os.path.join(HERE, 'out', dataset); os.makedirs(out, exist_ok=True)
    cache = os.path.join(HERE, 'cache', dataset)
    caps = ad.captures(root); res = dict(dataset=dataset, protocol=PROTOCOL, captures={}, integrity={}, signature={}, labels={}, scores={}, benign_test={})
    idcounts = {}
    for c in caps:
        a = core.load_cached(ad, c, cache)
        res['integrity'][c['name']], idcounts[c['name']] = core.integrity(a, c)
        res['captures'][c['name']] = dict(role=c['role'], family=c['family'], variant=c['variant'], intervals=c['intervals'])
        print('loaded', c['name'], len(a['ts']), flush=True); del a
    get = lambda name: core.load_cached(ad, next(x for x in caps if x['name'] == name), cache)
    benign = [c for c in caps if c['role'] == 'benign']
    def get_train(name):
        a = get(name); m = a['ts'] < TRAIN_FRAC * a['ts'][-1]
        return {k: a[k][m] for k in ('ts', 'id', 'data')}
    prof = core.build_profile(get_train, [c['name'] for c in benign])
    res['profile'] = dict(known_ids=int(len(prof['vocab'])))
    print('profile built', len(prof['vocab']), flush=True)
    # benign test: windows starting at/after TRAIN_FRAC * duration of every benign capture
    tot = {k: 0 for k in DETECTORS}; nwt = 0; fl = {k: 0 for k in ('id_whitelist', 'period', 'payload_range', 'byte_delta')}; nft = 0; store = {}
    for c in benign:
        a = get(c['name']); ev = core.evaluate(a, prof); dur = a['ts'][-1]
        first = int(np.ceil(TRAIN_FRAC * dur / WIN)); sel = np.arange(ev['nwin']) >= first
        store[c['name']] = ({k: v[sel] for k, v in ev['alarms'].items()}, int(sel.sum()))
        for k in tot: tot[k] += int(ev['alarms'][k][sel].sum())
        nwt += int(sel.sum()); ft = a['ts'] >= TRAIN_FRAC * dur; nft += int(ft.sum())
        for k in fl: fl[k] += int(ev['flags'][k][ft].sum())
        del a, ev
    fpr = {k: tot[k] / nwt for k in tot}
    usable = [k for k in DETECTORS if fpr[k] <= PROTOCOL['fpr_gate']]
    anyu = 0
    for nm, (al, nsel) in store.items():
        comb = core.combine(al, usable); anyu += int(comb.sum())
        res['benign_test'][nm] = dict(test_windows=nsel, window_alarm_rate={**{k: float(v.mean()) for k, v in al.items()}, 'any_usable': float(comb.mean())})
    fpr['any_usable'] = anyu / nwt
    res['fpr'] = dict(test_windows=nwt, window_fpr=fpr, test_frames=nft, frame_flag_rate={k: fl[k] / nft for k in fl}, usable_detectors=usable)
    print('FPR', fpr, 'usable', usable, flush=True)
    for c in [c for c in caps if c['role'] == 'attack']:
        a = get(c['name']); ev = core.evaluate(a, prof); ev['alarms']['any_usable'] = core.combine(ev['alarms'], usable)
        res['scores'][c['name']] = core.score_attack(a, ev, c['intervals'])
        if c['intervals']:
            res['signature'][c['name']] = core.signature(a, c['intervals'])
        fl_ = ad.frame_labels(c)
        if fl_ is not None:
            res['labels'][c['name']] = core.label_audit(*fl_, c['intervals'])
        print('attack', c['name'], res['scores'][c['name']].get('recall', {}).get('any_usable'), flush=True)
    json.dump(res, open(os.path.join(out, 'results.json'), 'w'), indent=1, default=str)
    import pandas as pd
    pd.DataFrame(idcounts).fillna(0).astype(int).to_csv(os.path.join(out, 'id_counts.csv'))
    print('DONE in', round(time.time() - t_all), 's', flush=True)

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
