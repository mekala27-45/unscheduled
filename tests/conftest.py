from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("UNSCHED_ROOT", str(ROOT))
# The numeric pins the models workflow sets, set here before any test imports numpy, so the suite
# runs the kernels CI runs and the scripts that require them start. The module imports nothing else.
from unscheduled_models.numerics import PINS  # noqa: E402

for _name, _value in PINS.items():
    os.environ.setdefault(_name, _value)
