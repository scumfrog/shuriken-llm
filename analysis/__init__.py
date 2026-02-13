"""
shuriken.analysis — Detection and scoring pipeline.

Usage:
    from shuriken.analysis import run_all_detectors, score_detections, DetectorContext
"""
from .detectors import (
    DetectorContext,
    BaseDetector,
    run_all_detectors,
    list_detectors,
    register_detector,
    get_detector,
)
from .scoring import (
    Scorer,
    ScoringResult,
    ScoringRule,
    score_detections,
)

__all__ = [
    "DetectorContext",
    "BaseDetector",
    "run_all_detectors",
    "list_detectors",
    "register_detector",
    "get_detector",
    "Scorer",
    "ScoringResult",
    "ScoringRule",
    "score_detections",
]
