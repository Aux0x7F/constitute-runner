#!/usr/bin/env node
import fs from "node:fs";
import {
  appRunnerFulfillmentFixture,
  buildAppRunnerFulfillment,
  buildAppRunnerFulfillmentLifecycle,
  buildMultiIdentityGrantProof,
  buildCybersecProcessorRun,
  multiIdentityGrantFixture,
  cybersecAppContractFixture,
  cybersecBootstrapFixture,
} from "./index.js";

function argValue(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) return "";
  return String(process.argv[index + 1] || "");
}

function usage() {
  console.log("Usage: constitute-runner --fixture cybersec-bootstrap|cybersec-app-contract|multi-identity-grant|app-fulfillment|app-lifecycle | --input <json-file>");
}

const fixture = argValue("--fixture");
const inputPath = argValue("--input");
let input;

if (fixture === "cybersec-bootstrap") {
  console.log(JSON.stringify(buildCybersecProcessorRun(cybersecBootstrapFixture()), null, 2));
  process.exit(0);
} else if (fixture === "cybersec-app-contract") {
  console.log(JSON.stringify(cybersecAppContractFixture(), null, 2));
  process.exit(0);
} else if (fixture === "multi-identity-grant") {
  console.log(JSON.stringify(buildMultiIdentityGrantProof(multiIdentityGrantFixture()), null, 2));
  process.exit(0);
} else if (fixture === "app-fulfillment") {
  console.log(JSON.stringify(buildAppRunnerFulfillment(appRunnerFulfillmentFixture()), null, 2));
  process.exit(0);
} else if (fixture === "app-lifecycle") {
  console.log(JSON.stringify(buildAppRunnerFulfillmentLifecycle(appRunnerFulfillmentFixture()), null, 2));
  process.exit(0);
} else if (inputPath) {
  input = JSON.parse(fs.readFileSync(inputPath, "utf8"));
} else {
  usage();
  process.exit(1);
}

const report = input.appContract && input.manifest
  ? (input.lifecycle ? buildAppRunnerFulfillmentLifecycle(input) : buildAppRunnerFulfillment(input))
  : buildCybersecProcessorRun(input);
console.log(JSON.stringify(report, null, 2));
