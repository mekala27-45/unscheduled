"""The numeric kernels a model fit runs with, pinned so the same fit gives the same numbers anywhere.

OpenBLAS chooses its kernels for the processor it finds and splits work over the threads it is
given, and numpy chooses its own vector code for the processor when it is imported. Both move
floating point sums in their last bits from one machine to the next. liblinear takes its vector
operations from scipy's OpenBLAS, so the out of fold refits of the band floor differ in those bits,
and a fifty trial search over folds with few listings turns them into different trees (DECISIONS.md,
the exploitation step pins its numeric kernels). The models workflow and reset and rederive set
these variables before Python starts; they take effect only if they are set before numpy and scipy
are imported. Every x86-64 runner GitHub offers, and the build machine, runs the Haswell kernels.
"""

from __future__ import annotations

import importlib
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

PINS: dict[str, str] = {
    # OpenBLAS: one kernel family on every processor, and one thread, so no sum is split by core.
    "OPENBLAS_CORETYPE": "Haswell",
    "OPENBLAS_NUM_THREADS": "1",
    # numpy: no AVX-512 code paths, so a machine with them runs what a machine without them runs.
    "NPY_DISABLE_CPU_FEATURES": "X86_V4 AVX512_ICL AVX512_SPR",
}


def missing(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The pins the environment does not hold, each with the value it should have."""
    env = os.environ if environ is None else environ
    return {name: value for name, value in PINS.items() if env.get(name) != value}


def processor() -> str | None:
    """The processor's name as the kernel reports it, where it does."""
    info = Path("/proc/cpuinfo")
    if not info.exists():
        return None
    for line in info.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    return None


def describe() -> dict[str, Any]:
    """What this process runs with, read back from the libraries rather than assumed from the
    variables: the OpenBLAS kernels and threads, and the numpy code paths switched on."""
    from threadpoolctl import threadpool_info

    blas = [
        {"library": i.get("prefix"), "architecture": i.get("architecture"), "threads": i.get("num_threads")}
        for i in threadpool_info()
        if i.get("internal_api") == "openblas"
    ]
    try:
        umath = importlib.import_module("numpy._core._multiarray_umath")
        features = getattr(umath, "__cpu_features__", {})
        dispatch: list[str] | None = [
            str(name) for name in getattr(umath, "__cpu_dispatch__", []) if features.get(name)
        ]
    except ImportError:
        dispatch = None
    return {
        "processor": processor(),
        "pins": {name: os.environ.get(name) for name in PINS},
        "openblas": blas,
        "numpy_dispatch": dispatch,
    }
