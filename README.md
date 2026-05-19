# constitute-runner

`constitute-runner` is the first-party execution helper for contract-backed
app and processor fulfillment.

It validates runner operations, checks processor seeds and surface app
contracts, enforces resource and secret boundaries, and emits safe execution
posture for alert, evidence-hold, app fulfillment, release, and proof workflows.
It does not own event semantics, storage semantics, logging semantics, product
UI state, or app source selection.

## Commands

```bash
npm test
npm run build
node src/cli.mjs --fixture cybersec-bootstrap
node src/cli.mjs --fixture cybersec-app-contract
node src/cli.mjs --fixture app-fulfillment
```
