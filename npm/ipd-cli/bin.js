#!/usr/bin/env node
// Wrapper for `npx ipd-cli`. It does not download a binary.
// Install the Go binary as `ipd` on PATH, or set IPD_BIN.
const { spawn } = require("child_process");
const bin = process.env.IPD_BIN || "ipd";
const child = spawn(bin, process.argv.slice(2), { stdio: "inherit" });
child.on("error", (err) => {
  console.error("找不到 ipd 二进制。先在本机执行 go build -o ipd ./cmd/ipd，或设置 IPD_BIN。");
  console.error(String(err));
  process.exit(127);
});
child.on("exit", (code) => process.exit(code == null ? 1 : code));
