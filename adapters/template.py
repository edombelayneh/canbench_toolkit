"""Adapter template. Copy to adapters/<dataset>.py and fill in. Each capture is a dict:
  name, role ('benign'|'attack'), family (attack family or None), variant ('plain'|'masquerade'|None),
  intervals ([[start_s, end_s], ...] elapsed seconds from first frame, or [] if unknown/no injection),
  meta ({'elapsed_sec':..., plus anything useful}), path.
Dataset-specific parsing goes in load(cap) and must return normalized arrays:
  ts (float64 seconds from first frame), id (uint32), data (uint8 [n,8], zero padded), dlc (uint8), t0 (float).
Never read anything from the user's summary table; read only files in the dataset folder."""
from core import parse_candump

class Adapter:
    name = 'TEMPLATE'
    def captures(self, root):
        raise NotImplementedError
    def load(self, cap):
        return parse_candump(cap['path'])      # for SocketCAN-style logs; otherwise write a CSV/other reader
    def frame_labels(self, cap):
        return None                              # or (ts, id, label) numpy arrays when the dataset ships per-frame labels
