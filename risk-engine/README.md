# Risk Engine

The risk engine converts evidence into an explainable bounded score.

## Initial model

Risk should combine:

- detection severity
- detection confidence
- evidence quality
- affected asset criticality
- number and strength of correlated indicators
- uncertainty and missing telemetry

The output must include both the numeric score and a list of contributing factors. Do not use a black-box model in the foundation phase.

## Safety

Risk scoring is advisory. A score alone must not authorize destructive or disruptive actions.