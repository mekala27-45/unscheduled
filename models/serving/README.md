# The serving models

The files the API reads to serve predictions, each written by a script from committed records and
checked before it is kept. Nothing here is edited by hand.

| File | Written by | Read by |
| --- | --- | --- |
| band_floor.onnx | scripts/export_onnx.py | POST /v1/predict: the band floor's linear part |
| band_floor.json.gz | scripts/export_onnx.py | POST /v1/predict: the floor's vocabularies, columns and offsets |
| exploit_lgbm.onnx | scripts/export_onnx.py | POST /v1/predict: the exploitation model |
| exploit_day0.json | scripts/export_onnx.py | POST /v1/predict: the exploitation model's day 0 row |
| serving.json | scripts/predict_serving.py | POST /v1/predict: temperatures, the conformal cutoff, the isotonic map, the batch quantiles |
| predictions.parquet | scripts/predict_serving.py | the serving bundle (scripts/build_serving_bundle.py), loaded into Neon by the sync |

results/models/onnx.json holds the parity of each ONNX file with its native model on development
rows built the API's way, and results/models/predictions.json the batch with its digest. Until the
files exist, POST /v1/predict answers that the models are not in this deployment, and the bundle
carries no predictions.
