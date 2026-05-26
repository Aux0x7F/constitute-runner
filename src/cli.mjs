#!/usr/bin/env node
import fs from "node:fs";
import {
  appRunnerFulfillmentFixture,
  buildRunnerBuildOperationFixture,
  buildRunnerModuleLoadOperationFixture,
  buildAppRunnerFulfillment,
  buildAppRunnerFulfillmentLifecycle,
  buildMultiIdentityGrantProof,
  buildRunnerHostFulfillmentPosture,
  buildRunnerOperationForBuild,
  buildRunnerOperationForModuleLoad,
  fulfillAcceptedRuntimeRunnerDispatches,
  fulfillRunnerOperationDispatch,
  multiIdentityGrantFixture,
} from "./index.js";

function argValue(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) return "";
  return String(process.argv[index + 1] || "");
}

function usage() {
  console.log("Usage: constitute-runner --fixture multi-identity-grant|app-fulfillment|app-lifecycle|build-operation|module-load | --input <json-file>");
}

const fixture = argValue("--fixture");
const inputPath = argValue("--input");
let input;

if (fixture === "multi-identity-grant") {
  console.log(JSON.stringify(buildMultiIdentityGrantProof(multiIdentityGrantFixture()), null, 2));
  process.exit(0);
} else if (fixture === "app-fulfillment") {
  console.log(JSON.stringify(buildAppRunnerFulfillment(appRunnerFulfillmentFixture()), null, 2));
  process.exit(0);
} else if (fixture === "app-lifecycle") {
  console.log(JSON.stringify(buildAppRunnerFulfillmentLifecycle(appRunnerFulfillmentFixture()), null, 2));
  process.exit(0);
} else if (fixture === "build-operation") {
  console.log(JSON.stringify(buildRunnerBuildOperationFixture(), null, 2));
  process.exit(0);
} else if (fixture === "module-load") {
  console.log(JSON.stringify(buildRunnerModuleLoadOperationFixture(), null, 2));
  process.exit(0);
} else if (inputPath) {
  input = JSON.parse(fs.readFileSync(inputPath, "utf8"));
} else {
  usage();
  process.exit(1);
}

if (input.buildContract && input.buildRun) {
  console.log(JSON.stringify(buildRunnerOperationForBuild(input), null, 2));
  process.exit(0);
}

if (input.runnerOperation && (input.fulfillDispatch || input.dispatchFulfillment || input.runtimeDispatch)) {
  console.log(JSON.stringify(fulfillRunnerOperationDispatch(input), null, 2));
  process.exit(0);
}

if (input.runtimeRunnerBridge || input.runnerDispatchBridge || input.runtimeSnapshot || input.dispatches || input.runnerOperations) {
  console.log(JSON.stringify(await fulfillAcceptedRuntimeRunnerDispatches(input), null, 2));
  process.exit(0);
}

if (input.moduleRef || input.processorModuleRef || input.nativeModuleRef || input.moduleResolverPosture || input.moduleResolutionPosture) {
  const runnerOperation = buildRunnerOperationForModuleLoad(input);
  if (input.emitHostPosture || input.serviceRefs || input.witnessRefs) {
    console.log(JSON.stringify({
      runnerOperation,
      hostPosture: buildRunnerHostFulfillmentPosture({
        ...input,
        runnerOperation,
      }),
    }, null, 2));
    process.exit(0);
  }
  console.log(JSON.stringify(runnerOperation, null, 2));
  process.exit(0);
}

if (!input.appContract || !input.manifest) {
  console.error("Runner input must declare appContract and manifest. Domain processors live with their app contract.");
  process.exit(1);
}

const report = input.lifecycle ? buildAppRunnerFulfillmentLifecycle(input) : buildAppRunnerFulfillment(input);
console.log(JSON.stringify(report, null, 2));
