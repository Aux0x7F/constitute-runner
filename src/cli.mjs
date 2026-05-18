#!/usr/bin/env node
import fs from "node:fs";
import {
  buildSecurityProcessorRun,
  securityBootstrapFixture,
} from "./index.js";

function argValue(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) return "";
  return String(process.argv[index + 1] || "");
}

function usage() {
  console.log("Usage: constitute-runner --fixture security-bootstrap | --input <json-file>");
}

const fixture = argValue("--fixture");
const inputPath = argValue("--input");
let input;

if (fixture === "security-bootstrap") {
  input = securityBootstrapFixture();
} else if (inputPath) {
  input = JSON.parse(fs.readFileSync(inputPath, "utf8"));
} else {
  usage();
  process.exit(1);
}

const report = buildSecurityProcessorRun(input);
console.log(JSON.stringify(report, null, 2));
