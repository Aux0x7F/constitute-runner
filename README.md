# constitute-runner

`constitute-runner` is the first-party execution helper for contract-backed
app and processor fulfillment.

It validates runner operations, checks processor seeds, enforces resource and
secret boundaries, and emits safe execution posture for alert, evidence-hold,
release, and proof workflows. It does not own event semantics, storage
semantics, logging semantics, or product UI state.
