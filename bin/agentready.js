#!/usr/bin/env node

import { runCli } from "../src/cli.js";
import { AgentReadyError } from "../src/errors.js";

runCli(process.argv.slice(2)).catch((error) => {
  // Known AgentReadyErrors carry a curated, actionable message regardless of
  // exit code, so print just that; only truly unexpected errors get the full
  // stack to aid debugging.
  if (error instanceof AgentReadyError) {
    console.error(error.message);
  } else {
    console.error(error?.stack || error?.message || String(error));
  }
  process.exit(error?.exitCode || 4);
});
