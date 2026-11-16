"""AegisGate analysis core.

Pure-Python implementation of the security decision pipeline:

    canonical events -> detection -> behaviour baseline -> correlation
    -> explainable risk -> policy decision

Nothing in this package imports FastAPI or the database layer, so every
stage can be unit-tested on its own. See docs/03-analysis-core.md for the
documented thresholds, weights and limitations.
"""

CORE_VERSION = "core-1.0.0"
