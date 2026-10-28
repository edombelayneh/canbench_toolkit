"""canbench core: dataset-agnostic CAN IDS test battery. PROTOCOL v1 is fixed so every dataset is tested identically."""
import os, json, math
import numpy as np, pandas as pd

PROTOCOL = dict(version=1, win_s=1.0, train_frac=0.7, gap_factor=0.5, rate_up=1.10, rate_low=0.90, min_gaps=30, min_flags=3, fpr_gate=0.05)
WIN = PROTOCOL['win_s']; TRAIN_FRAC = PROTOCOL['train_frac']
DETECTORS = ['id_whitelist', 'period', 'rate', 'payload_range', 'byte_delta']

_HEX = np.zeros(256, np.uint8)
for _i, _c in enumerate('0123456789abcdef'):
    _HEX[ord(_c)] = _i; _HEX[ord(_c.upper())] = _i

def _hex_matrix(series, width):
    arr = series.to_numpy().astype('S%d' % width)
    b = np.frombuffer(arr.tobytes(), dtype=np.uint8).reshape(len(arr), width)
    return _HEX[b]

def parse_candump(path, chunksize=1_000_000):
    """SocketCAN/candump -L style: '(ts) iface ID#DATA'. Returns normalized arrays (ts relative to first frame)."""
    T, I, D, L = [], [], [], []
    for ch in pd.read_csv(path, sep=' ', header=None, names=['ts', 'bus', 'frame'], dtype=str, chunksize=chunksize):
        ts = ch['ts'].str.slice(1, -1).astype('float64').to_numpy()
        part = ch['frame'].str.partition('#')
        ids = part[0]; w = int(ids.str.len().max())
        v = _hex_matrix(ids.str.zfill(w), w).astype(np.uint32)
        idv = np.zeros(len(v), np.uint32)
        for k in range(w):
            idv = (idv << 4) | v[:, k]
        dstr = part[2].fillna('')
        dlc = (dstr.str.len() // 2).clip(upper=8).to_numpy().astype(np.uint8)
        dv = _hex_matrix(dstr.str.slice(0, 16).str.pad(16, side='right', fillchar='0'), 16)
        T.append(ts); I.append(idv); D.append(((dv[:, 0::2] << 4) | dv[:, 1::2]).astype(np.uint8)); L.append(dlc)
    ts = np.concatenate(T); t0 = float(ts[0])
    return dict(ts=ts - t0, id=np.concatenate(I), data=np.concatenate(D), dlc=np.concatenate(L), t0=t0)

def load_cached(adapter, cap, cache_dir):
    p = os.path.join(cache_dir, cap['name'] + '.npz')
    if os.path.exists(p):
        z = np.load(p); return {k: z[k] for k in z.files}
    a = adapter.load(cap); os.makedirs(cache_dir, exist_ok=True); np.savez(p, **a); return a

# ---------- stage 1: integrity ----------
def integrity(a, cap):
    ts, ids = a['ts'], a['id']; n = len(ts); dur = float(ts[-1]); dts = np.diff(ts)
    u, c = np.unique(ids, return_counts=True)
    r = dict(n_frames=int(n), duration_s=dur, meta_elapsed_s=cap['meta'].get('elapsed_sec'),
             monotonic=bool((dts >= 0).all()), frames_per_s=n / dur, unique_ids=int(len(u)),
             ids_over_0x7FF=[hex(int(x)) for x in u if x > 0x7FF][:10],
             dlc_dist={int(k): int(v) for k, v in zip(*np.unique(a['dlc'], return_counts=True))},
             gaps_over_100ms=int((dts > 0.1).sum()), max_gap_s=float(dts.max()), max_gap_at_s=float(ts[int(dts.argmax())]),
             median_gap_us=float(np.median(dts) * 1e6), mean_gap_us=float(dts.mean() * 1e6), frac_gaps_under_5us=float((dts < 5e-6).mean()))
    top = np.argsort(-c)[:3]
    r['top_ids'] = [(hex(int(u[i])), float(c[i] / dur)) for i in top]
    return r, dict(zip(u.tolist(), c.tolist()))

# ---------- stage 2: baseline profile (benign, first TRAIN_FRAC of each capture) ----------
def _group(idx, ts, data):
    order = np.argsort(idx, kind='stable')
    i_s = idx[order]; t_s = ts[order]; d_s = data[order].astype(np.int16)
    same = np.zeros(len(idx), bool); same[1:] = (i_s[1:] == i_s[:-1]) & (i_s[1:] >= 0)
    gap = np.zeros(len(idx)); gap[1:] = t_s[1:] - t_s[:-1]
    dlt = np.zeros_like(d_s); dlt[1:] = np.abs(d_s[1:] - d_s[:-1])
    return order, i_s, same, gap, dlt, d_s

def build_profile(get_train, names):
    """get_train(name) -> dict(ts, id, data) for the first TRAIN_FRAC of one benign capture. Streams one capture at a time."""
    ids_all = set()
    for nm in names:
        t = get_train(nm); ids_all |= set(np.unique(t['id']).tolist()); del t
    vocab = np.array(sorted(ids_all), dtype=np.uint32); K = len(vocab)
    bmin = np.full((K, 8), 255, np.int16); bmax = np.zeros((K, 8), np.int16); dmax = np.zeros((K, 8), np.int16)
    rmin = np.full(K, 10 ** 9, np.int64); rmax = np.zeros(K, np.int64)
    gid, gx = [], []
    for nm in names:
        a = get_train(nm)
        idx = np.searchsorted(vocab, a['id']).astype(np.int64)
        order, i_s, same, gap, dlt, d_s = _group(idx, a['ts'], a['data'])
        starts = np.flatnonzero(np.r_[True, i_s[1:] != i_s[:-1]]); who = i_s[starts]
        bmin[who] = np.minimum(bmin[who], np.minimum.reduceat(d_s, starts, axis=0))
        bmax[who] = np.maximum(bmax[who], np.maximum.reduceat(d_s, starts, axis=0))
        dlt[~same] = 0
        dmax[who] = np.maximum(dmax[who], np.maximum.reduceat(dlt, starts, axis=0))
        gid.append(i_s[same].astype(np.int16)); gx.append(gap[same].astype(np.float32))
        nw = int(math.floor(a['ts'][-1] / WIN)); w = (a['ts'] / WIN).astype(np.int64); m = w < nw
        if nw > 0:
            cnt = np.bincount(w[m] * K + idx[m], minlength=nw * K).reshape(nw, K)
            rmin = np.minimum(rmin, cnt.min(0)); rmax = np.maximum(rmax, cnt.max(0))
        del a, order, i_s, same, gap, dlt, d_s, idx
    df = pd.DataFrame({'g': np.concatenate(gid), 'x': np.concatenate(gx)}); del gid, gx
    q = df.groupby('g').x.quantile(0.01); nn = df.groupby('g').x.size()
    thr = np.zeros(K)
    for k in q.index:
        if nn[k] >= PROTOCOL['min_gaps']:
            thr[k] = PROTOCOL['gap_factor'] * float(q[k])
    up = np.ceil(rmax * PROTOCOL['rate_up']) + 1
    low = np.where(rmin > 0, np.floor(rmin * PROTOCOL['rate_low']), -1)
    return dict(vocab=vocab, bmin=bmin, bmax=bmax, dmax=dmax, gap_thr=thr, rate_up=up, rate_low=low)

# ---------- stage 3: detectors ----------
def evaluate(a, prof):
    ts, ident = a['ts'], a['id']; vocab = prof['vocab']; K = len(vocab); n = len(ts)
    idx = np.minimum(np.searchsorted(vocab, ident), K - 1).astype(np.int64)
    known = vocab[idx] == ident; idx = np.where(known, idx, -1)
    order, i_s, same, gap, dlt, d_s = _group(idx, ts, a['data'])
    iz = np.maximum(i_s, 0)
    flags = {'id_whitelist': ~known}
    f = np.zeros(n, bool); f[order[same & (prof['gap_thr'][iz] > 0) & (gap < prof['gap_thr'][iz])]] = True; flags['period'] = f
    d = a['data'].astype(np.int16); iz2 = np.maximum(idx, 0)
    flags['payload_range'] = known & ((d < prof['bmin'][iz2]) | (d > prof['bmax'][iz2])).any(1)
    f = np.zeros(n, bool); f[order[same & (dlt > prof['dmax'][iz]).any(1)]] = True; flags['byte_delta'] = f
    nwin = int(math.floor(ts[-1] / WIN)); w = (ts / WIN).astype(np.int64); m = (w < nwin)
    alarms = {}
    for k in ('id_whitelist', 'period', 'payload_range', 'byte_delta'):
        alarms[k] = np.bincount(w[flags[k] & m], minlength=nwin)[:nwin] >= PROTOCOL['min_flags']
    mk = m & known
    cnt = np.bincount(w[mk] * K + idx[mk], minlength=nwin * K).reshape(nwin, K)
    alarms['rate'] = ((cnt > prof['rate_up']) | ((prof['rate_low'] >= 0) & (cnt < prof['rate_low']))).any(1)
    return dict(nwin=nwin, alarms=alarms, flags=flags, known=known)

def combine(alarms, usable):
    return np.logical_or.reduce([alarms[k] for k in usable]) if usable else np.zeros_like(alarms['rate'])

def attack_window_truth(nwin, intervals):
    t = np.zeros(nwin, bool); wi = np.arange(nwin)
    for s, e in intervals:
        t |= (wi < e) & (wi + WIN > s)
    return t

def score_attack(a, ev, intervals):
    nwin = ev['nwin']; truth = attack_window_truth(nwin, intervals) if intervals else None
    out = dict(n_windows=nwin)
    if truth is None or not truth.any():
        out['attack_windows'] = 0
        out['alarm_rate_all_windows'] = {k: float(v.mean()) for k, v in ev['alarms'].items()}
        return out
    out['attack_windows'] = int(truth.sum()); out['clean_windows'] = int((~truth).sum())
    out['recall'] = {k: float(v[truth].mean()) for k, v in ev['alarms'].items()}
    out['clean_window_alarm_rate'] = {k: (float(v[~truth].mean()) if (~truth).any() else None) for k, v in ev['alarms'].items()}
    s0 = min(s for s, e in intervals); ts = a['ts']; delay = {}
    for k in ('id_whitelist', 'period', 'payload_range', 'byte_delta'):
        sel = ev['flags'][k] & (ts >= s0)
        delay[k] = float(ts[sel][0] - s0) if sel.any() else None
    ra = np.flatnonzero(ev['alarms']['rate'] & (np.arange(nwin) + WIN > s0))
    delay['rate'] = float(max(0.0, ra[0] + WIN - s0)) if len(ra) else None
    out['first_alarm_delay_s'] = delay
    return out

# ---------- stage 4: attack signature (generic, no metadata target needed) ----------
def signature(a, intervals):
    ts, ids, data = a['ts'], a['id'], a['data']; dur = float(ts[-1])
    inw = np.zeros(len(ts), bool); t_in = 0.0
    for s, e in intervals:
        inw |= (ts >= s) & (ts <= e); t_in += e - s
    t_out = dur - t_in
    out = dict(window_s=t_in, window_share=t_in / dur, bus_fps_in=float(inw.sum() / t_in), bus_fps_out=float((~inw).sum() / t_out) if t_out > 0 else None)
    u_in, c_in = np.unique(ids[inw], return_counts=True); u_out, c_out = np.unique(ids[~inw], return_counts=True)
    out['ids_in_window'] = int(len(u_in)); out['ids_only_in_window'] = int(len(set(u_in.tolist()) - set(u_out.tolist())))
    cin = dict(zip(u_in.tolist(), c_in.tolist())); cout = dict(zip(u_out.tolist(), c_out.tolist()))
    rows = []
    for i, ci in cin.items():
        co = cout.get(i, 0)
        if ci >= 20 and co >= 20 and t_out > 0:
            rows.append((ci / t_in / (co / t_out), i, ci, co))
    rows.sort(reverse=True); top = []
    for ratio, i, ci, co in rows[:3]:
        sel = ids == i; t = ts[sel]; d = data[sel]; chg = (d[1:] != d[:-1]).sum(1); tin = inw[sel][1:]; gp = np.diff(t) * 1e3
        top.append(dict(id=hex(int(i)), rate_ratio=float(ratio), rate_in=ci / t_in, rate_out=co / t_out,
                        median_gap_ms_in=float(np.median(gp[tin])) if tin.any() else None, median_gap_ms_out=float(np.median(gp[~tin])) if (~tin).any() else None,
                        mean_bytes_changed_in=float(chg[tin].mean()) if tin.any() else None, mean_bytes_changed_out=float(chg[~tin].mean()) if (~tin).any() else None))
    out['top_rate_ratio_ids'] = top
    return out

def intervals_from_labels(ts, lab, merge_gap=1.0):
    """For datasets that ship only per-frame labels: turn attack-labeled frames into [start, end] intervals (runs merged when gaps are under merge_gap seconds), in the same elapsed-seconds clock as the frames."""
    t = ts[lab == 1]
    if len(t) == 0:
        return []
    br = np.flatnonzero(np.diff(t) > merge_gap)
    s = np.r_[t[0], t[br + 1]]; e = np.r_[t[br], t[-1]]
    return [[float(a), float(b)] for a, b in zip(s, e)]

# ---------- stage 5: label audit (optional adapter hook frame_labels -> (ts, id, label)) ----------
def label_audit(lts, lid, lab, intervals):
    out = dict(rows=int(len(lab)), label1=int((lab == 1).sum()), label1_share=float((lab == 1).mean()))
    if (lab == 1).any():
        t1 = lts[lab == 1]; out['first_label1_s'] = float(t1.min()); out['last_label1_s'] = float(t1.max())
        if intervals:
            s0 = min(s for s, e in intervals); e0 = max(e for s, e in intervals)
            out['interval'] = [s0, e0]; out['label1_outside_interval'] = int(((t1 < s0 - 1e-4) | (t1 > e0 + 1e-4)).sum())
            out['first_label1_minus_start_s'] = float(t1.min() - s0); out['end_minus_last_label1_s'] = float(e0 - t1.max())
    return out
