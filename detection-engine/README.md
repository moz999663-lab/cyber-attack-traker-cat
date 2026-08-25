# Detection Engine

The detection engine evaluates normalized events against defensive rules and behavioral indicators.

## Detection contract

A detector should return:

```text
DetectionResult
- detection_id
- rule_id
- severity
- confidence
- title
- explanation
- evidence_event_ids[]
- observed_at
```

Rules must be deterministic, versioned, testable, and explainable. A rule must never trigger an offensive action directly.

## Initial detectors

Start with safe synthetic scenarios and generic behavioral signals, for example impossible event sequences, unexpected parent/child relationships in simulated data, and unusual outbound connection metadata. Real-world thresholds should be configurable and tested against false positives.