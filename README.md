# constitute-runner

`constitute-runner` is the first-party execution helper for contract-backed app
fulfillment and runner host posture.

It validates runner operations, surface app contracts, resource and secret
boundaries, and safe execution posture for app fulfillment, release, and proof
workflows. Domain processor contracts live with their owning app repos and call
the generic runner helpers. The runner does not own domain event semantics,
storage semantics, product UI state, or app source selection.

## Commands

```bash
npm test
npm run build
node src/cli.mjs --fixture app-fulfillment
node src/cli.mjs --fixture app-lifecycle
node src/cli.mjs --fixture build-operation
```

The build-operation fixture is runner-side evidence only: it reports accepted,
completed, resource, proof, and release-candidate refs for a build contract
without making the runner own source, build, storage, or app semantics.
