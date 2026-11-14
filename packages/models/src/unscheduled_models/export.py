"""The ONNX exports /v1/predict runs, and the specs the API builds their inputs from.

The band floor's linear part becomes an ONNX graph: one weight per column and class, the one versus
the rest sigmoids, and their scaling to one, which is what OneVsRestClassifier over liblinear's
logistic regressions computes. Its inputs become a spec that unscheduled_core.featurize reads: the
TF-IDF vocabularies and inverse document frequencies, the one hot columns with their infrequent
bucket, and the CWE list columns. LightGBM becomes ONNX through onnxmltools, its day 0 row a spec of
the same kind. The parity functions build the inputs the API's way, from plain rows, and compare the
ONNX probabilities with the native ones (evaluation: within 1e-4).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

import numpy as np
import onnx
import polars as pl
from onnx import TensorProto, helper, numpy_helper
from unscheduled_core.featurize import DayZeroRow, FloorFeatures

from unscheduled_models.features import MULTI, Features

OPSET = 15
TOLERANCE = 1e-4


def _vectorizer_spec(vectorizer: Any) -> dict[str, Any]:
    return {
        "analyzer": vectorizer.analyzer,
        "ngram_range": list(vectorizer.ngram_range),
        "lowercase": bool(vectorizer.lowercase),
        "token_pattern": vectorizer.token_pattern,
        "sublinear_tf": bool(vectorizer.sublinear_tf),
        "vocabulary": {str(k): int(v) for k, v in vectorizer.vocabulary_.items()},
        "idf": [float(v) for v in vectorizer.idf_],
    }


def floor_spec(features: Features) -> dict[str, Any]:
    """Everything FloorFeatures needs to rebuild a floor's input row, with the block offsets."""
    vectorizers = [features.word] + ([features.char] if features.char is not None else [])
    for v in vectorizers:
        if v.norm != "l2" or not v.use_idf or v.strip_accents is not None or v.preprocessor is not None:
            raise ValueError("the spec covers lower case, l2, idf and no accent stripping only")
    encoder = features.onehot
    onehot: list[dict[str, Any]] = []
    start = 0
    infrequent_sets = encoder.infrequent_categories_
    for name, categories, infrequent in zip(
        encoder.feature_names_in_, encoder.categories_, infrequent_sets, strict=True
    ):
        rare = set(infrequent) if infrequent is not None else set()
        frequent = [str(c) for c in categories if c not in rare]
        columns = {c: start + k for k, c in enumerate(frequent)}
        bucket = start + len(frequent) if rare else None
        onehot.append({"name": str(name), "columns": columns, "infrequent": bucket})
        start += len(frequent) + (1 if rare else 0)
    if start != len(encoder.get_feature_names_out()):
        raise ValueError(
            f"the one hot spec has {start} columns, the encoder {len(encoder.get_feature_names_out())}"
        )
    lists: list[dict[str, Any]] = []
    start_lists = 0
    for column in MULTI:
        classes = [str(c) for c in features.multi[column].classes_]
        lists.append({"name": column, "columns": {c: start_lists + k for k, c in enumerate(classes)}})
        start_lists += len(classes)
    widths = [len(v.vocabulary_) for v in vectorizers] + [start, start_lists]
    offsets = [int(sum(widths[:i])) for i in range(len(widths))]
    return {
        "variant": features.variant,
        "text": [_vectorizer_spec(v) for v in vectorizers],
        "onehot": onehot,
        "lists": lists,
        "offsets": offsets,
        "width": int(sum(widths)),
    }


def linear_onnx(estimators: Sequence[Any], classes: Sequence[str], width: int, name: str) -> onnx.ModelProto:
    """One versus the rest over logistic regressions as an ONNX graph: features [N, width] in,
    probabilities [N, classes] out, in the order of classes."""
    k = len(estimators)
    weights = np.vstack([np.asarray(e.coef_, dtype=np.float32).reshape(-1) for e in estimators]).T
    bias = np.asarray([float(np.asarray(e.intercept_).reshape(-1)[0]) for e in estimators], dtype=np.float32)
    if weights.shape != (width, k):
        raise ValueError(f"the weights are {weights.shape}, expected {(width, k)}")
    if (k == 1 and len(classes) != 2) or (k > 1 and k != len(classes)):
        raise ValueError(f"{k} estimators for {len(classes)} classes")
    inits = [numpy_helper.from_array(weights, "W"), numpy_helper.from_array(bias, "B")]
    nodes = [
        helper.make_node("MatMul", ["features", "W"], ["logits"]),
        helper.make_node("Add", ["logits", "B"], ["shifted"]),
        helper.make_node("Sigmoid", ["shifted"], ["each"]),
    ]
    if k == 1:
        inits.append(numpy_helper.from_array(np.array([1.0], dtype=np.float32), "one"))
        nodes += [
            helper.make_node("Sub", ["one", "each"], ["rest"]),
            helper.make_node("Concat", ["rest", "each"], ["probabilities"], axis=1),
        ]
    else:
        inits.append(numpy_helper.from_array(np.array([1], dtype=np.int64), "axis"))
        nodes += [
            helper.make_node("ReduceSum", ["each", "axis"], ["total"], keepdims=1),
            helper.make_node("Div", ["each", "total"], ["probabilities"]),
        ]
    graph = helper.make_graph(
        nodes,
        name,
        [helper.make_tensor_value_info("features", TensorProto.FLOAT, [None, width])],
        [helper.make_tensor_value_info("probabilities", TensorProto.FLOAT, [None, len(classes)])],
        initializer=inits,
    )
    model = helper.make_model(
        graph, opset_imports=[helper.make_opsetid("", OPSET)], producer_name="unscheduled"
    )
    model.metadata_props.extend([onnx.StringStringEntryProto(key="classes", value=",".join(classes))])
    onnx.checker.check_model(model)
    return model


def lgbm_onnx(booster: Any, width: int) -> onnx.ModelProto:
    """A LightGBM binary booster as ONNX, probabilities [N, 2] out, no zipmap."""
    from onnxmltools import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType

    model: onnx.ModelProto = convert_lightgbm(
        booster,
        initial_types=[("features", FloatTensorType([None, width]))],
        target_opset=OPSET,
        zipmap=False,
    )
    return model


def day0_spec(design: Any) -> dict[str, Any]:
    """Everything DayZeroRow needs to rebuild the exploitation model's dense row."""
    from unscheduled_models import rank

    return {
        "numeric": list(rank.NUMERIC),
        "flags": list(rank.FLAGS),
        "categorical": [{"name": name, "codes": dict(design.codes[name])} for name in rank.CATEGORICAL],
        "lists": [{"name": c, "classes": [str(v) for v in design.multi[c].classes_]} for c in rank.MULTI],
        "projection": list(rank.PROJECTION),
    }


def session(model: onnx.ModelProto) -> Any:
    import onnxruntime as ort

    options = ort.SessionOptions()
    options.intra_op_num_threads = 1
    options.log_severity_level = 3
    return ort.InferenceSession(model.SerializeToString(), options, providers=["CPUExecutionProvider"])


def rows_of(frame: pl.DataFrame) -> list[dict[str, Any]]:
    return frame.to_dicts()


def floor_parity(
    model: Any, features: Features, frame: pl.DataFrame, spec: dict[str, Any], graph: onnx.ModelProto
) -> dict[str, float | int]:
    """The native floor against its spec and graph on the same rows: the largest difference in any
    feature and in any probability."""
    native_x = features.transform(frame)
    native = model.predict_proba(native_x)
    built = FloorFeatures(spec)
    dense = np.zeros((frame.height, built.width), dtype=np.float32)
    for i, row in enumerate(rows_of(frame)):
        for j, v in built.transform(row).items():
            dense[i, j] = v
    feature_gap = float(np.max(np.abs(native_x.toarray() - dense))) if frame.height else 0.0
    onnx_proba = session(graph).run(None, {"features": dense})[0]
    return {
        "rows": frame.height,
        "max_feature_difference": feature_gap,
        "max_probability_difference": float(np.max(np.abs(native - onnx_proba))) if frame.height else 0.0,
    }


def lgbm_parity(
    booster: Any, design: Any, frame: pl.DataFrame, spec: dict[str, Any], graph: onnx.ModelProto
) -> dict[str, float | int]:
    """The native booster on DayZero's dense matrix against the ONNX graph on rows built from the
    spec, the projection read from the frame."""
    native = np.asarray(booster.predict(design.dense(frame)), dtype=np.float64)
    built = DayZeroRow(spec)
    projection = frame.select(spec["projection"]).to_numpy().astype(np.float64)
    dense = np.array(
        [built.transform(row, list(projection[i])) for i, row in enumerate(rows_of(frame))], dtype=np.float32
    ).reshape(frame.height, built.width)
    onnx_proba = session(graph).run(None, {"features": dense})[1][:, 1]
    reference = design.dense(frame)
    missing = np.isnan(reference)
    if frame.height and not np.array_equal(missing, np.isnan(dense)):
        raise ValueError("the spec's row marks other values unknown than the design does")
    return {
        "rows": frame.height,
        "max_input_difference": float(np.max(np.abs(np.where(missing, 0, reference - dense))))
        if frame.height
        else 0.0,
        "max_probability_difference": float(np.max(np.abs(native - onnx_proba))) if frame.height else 0.0,
    }
