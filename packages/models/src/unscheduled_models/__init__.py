"""The models of Phase 2: what unscheduled predicts for a CVE the NVD will not analyze, and how sure.

Every module here reads the lake through the point in time training sets (unscheduled_models.sets),
never the lake tables directly, so no model can see a value known after the day a CVE was published.
"""
