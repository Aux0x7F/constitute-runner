#!/usr/bin/env node
import fs from "node:fs";
import {
  appRunnerFulfillmentFixture,
  buildAppRunnerFulfillment,
  buildMultiIdentityGrantProof,
  buildSecurityProcessorRun,
  multiIdentityGrantFixture,
  securityAppContractFixture,
  securityBootstrapFixture,
} from "./index.js";

function argValue(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) return "";
  return String(process.argv[index + 1] || "");
}

function usage() {
  console.log("Usage: constitute-runner --fixture security-bootstrap|security-app-contract|multi-identity-grant|app-fulfillment | --input <json-file>");
}

const fixture = argValue("--fixture");
const inputPath = argValue("--input");
let input;

if (fixture === "security-bootstrap") {
  console.log(JSON.stringify(buildSecurityProcessorRun(securityBootstrapFixture()), null, 2));
  process.exit(0);
} else if (fixture === "security-app-contract") {
  console.log(JSON.stringify(securityAppContractFixture(), null, 2));
  process.exit(0);
} else if (fixture === "multi-identity-grant") {
  console.log(JSON.stringify(buildMultiIdentityGrantProof(multiIdentityGrantFixture()), null, 2));
  process.exit(0);
} else if (fixture === "app-fulfillment") {
  console.log(JSON.stringify(buildAppRunnerFulfillment(appRunnerFulfillmentFixture()), null, 2));
  process.exit(0);
} else if (inputPath) {
  input = JSON.parse(fs.readFileSync(inputPath, "utf8"));
} else {
  usage();
  process.exit(1);
}

const report = input.appContract && input.manifest
  ? buildAppRunnerFulfillment(input)
  : buildSecurityProcessorRun(input);
console.log(JSON.stringify(report, null, 2));
