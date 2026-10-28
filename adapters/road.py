import os, re, json
import numpy as np, pandas as pd
from core import parse_candump

class Adapter:
    name = 'ROAD'
    def captures(self, root):
        caps = []
        am = json.load(open(os.path.join(root, 'ambient', 'capture_metadata.json')))
        for n, m in sorted(am.items()):
            caps.append(dict(name=n, role='benign', family=None, variant=None, intervals=[], meta=m, path=os.path.join(root, 'ambient', n + '.log')))
        at = json.load(open(os.path.join(root, 'attacks', 'capture_metadata.json')))
        for n, m in sorted(at.items()):
            masq = n.endswith('_masquerade'); base = n[:-len('_masquerade')] if masq else n
            fam = re.sub(r'_(\d)$', '', base)
            iv = [m['injection_interval']] if m.get('injection_interval') else []
            caps.append(dict(name=n, role='attack', family=fam, variant='masquerade' if masq else 'plain', intervals=iv, meta=m,
                             path=os.path.join(root, 'attacks', n + '.log'), root=root))
        return caps
    def load(self, cap):
        return parse_candump(cap['path'])
    def frame_labels(self, cap):
        p = os.path.join(cap['root'], 'signal_extractions', 'attacks', cap['name'] + '.csv')
        if cap['role'] != 'attack' or not os.path.exists(p):
            return None
        df = pd.read_csv(p, usecols=['Label', 'Time', 'ID'])
        return df['Time'].to_numpy(), df['ID'].to_numpy(), df['Label'].to_numpy()
