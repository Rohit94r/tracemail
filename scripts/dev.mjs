#!/usr/bin/env node

/**
 * Raven (SecureMailScope) — Unified Dev Server
 * Connects and runs both FastAPI (Port 8001) and Next.js (Port 3000) concurrently.
 * Handles auto-install of missing dependencies and clean shutdown on Ctrl+C.
 */

import { spawn, spawnSync, execSync } from "child_process";
import fs from "fs";
import path from "path";
import readline from "readline";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PLATFORM_DIR = path.resolve(__dirname, "..");

console.log("\x1b[38;2;255;101;0m%s\x1b[0m", `
  ___    __ __    _____  _  _ 
 | _ \\  / // /   | __\\ \\/ // /
 |   / / _  /    | _| \\  // _ \\
 |_|_\\/_//_/     |___|/_//_//_/
  SECUREMAILSCOPE // PASSIVE AIR-GAPPED FORENSICS
`);

console.log("\x1b[36m%s\x1b[0m", "Starting unified environment...\n");

// 1. Check if Node dependencies are installed
if (!fs.existsSync(path.join(PLATFORM_DIR, "node_modules"))) {
  console.log("\x1b[33m%s\x1b[0m", "[bootstrap] Installing dependencies with pnpm...");
  spawnSync("pnpm", ["install"], { cwd: PLATFORM_DIR, stdio: "inherit" });
}

// 2. Check if Python dependencies are installed
const pyCheck = spawnSync(
  "python3",
  ["-c", "import fastapi, uvicorn, scapy, cryptography, pydantic, pymongo, dns"],
  { cwd: PLATFORM_DIR }
);

if (pyCheck.status !== 0) {
  console.log("\x1b[33m%s\x1b[0m", "[bootstrap] Installing Python dependencies from backend/requirements.txt...");
  spawnSync("python3", ["-m", "pip", "install", "-r", "backend/requirements.txt"], {
    cwd: PLATFORM_DIR,
    stdio: "inherit",
  });
}

// 3. Clear existing stale processes on ports 8001 and 3000 if any
function freePort(port) {
  try {
    const pids = execSync(`lsof -ti:${port}`, { encoding: "utf8" }).trim().split("\n");
    for (const pid of pids) {
      const numPid = Number(pid.trim());
      if (numPid && !isNaN(numPid) && numPid !== process.pid) {
        console.log("\x1b[33m%s\x1b[0m", `[port-guard] Freeing port ${port} (PID ${numPid})...`);
        try {
          process.kill(numPid, "SIGTERM");
        } catch {}
      }
    }
  } catch {
    // Port is already free
  }
}

freePort(8001);
freePort(3000);

let backendProc = null;
let frontendProc = null;

function prefixStream(stream, prefix, colorCode) {
  if (!stream) return;
  const rl = readline.createInterface({ input: stream });
  rl.on("line", (line) => {
    const cleanLine = line.replace(/\x1b\[2J\x1b\[0;0H/g, "");
    if (cleanLine.trim()) {
      console.log(`\x1b[${colorCode}m${prefix}\x1b[0m ${cleanLine}`);
    }
  });
}

// 4. Start Python FastAPI Backend
console.log("\x1b[34m%s\x1b[0m", "[boot] Spawning FastAPI Backend on http://0.0.0.0:8001...");
backendProc = spawn(
  "python3",
  [
    "-m",
    "uvicorn",
    "backend.app.main:app",
    "--host",
    "0.0.0.0",
    "--port",
    "8001",
    "--reload",
    "--reload-dir",
    "backend/app",
  ],
  {
    cwd: PLATFORM_DIR,
    env: { ...process.env, PYTHONPATH: PLATFORM_DIR, PORT: "8001" },
  }
);

prefixStream(backendProc.stdout, "[backend]", "34"); // Blue
prefixStream(backendProc.stderr, "[backend]", "34");

// 5. Start Next.js Frontend
console.log("\x1b[35m%s\x1b[0m", "[boot] Spawning Next.js Frontend on http://localhost:3000...");
frontendProc = spawn("pnpm", ["dev:frontend"], {
  cwd: PLATFORM_DIR,
  env: {
    ...process.env,
    NEXT_PUBLIC_API_URL: "http://localhost:8001",
  },
});

prefixStream(frontendProc.stdout, "[frontend]", "35"); // Magenta
prefixStream(frontendProc.stderr, "[frontend]", "35");

// 6. Graceful shutdown handler
function cleanup() {
  console.log("\n\x1b[33m%s\x1b[0m", "[shutdown] Terminating background processes...");
  if (backendProc) {
    try {
      backendProc.kill("SIGTERM");
    } catch {}
  }
  if (frontendProc) {
    try {
      frontendProc.kill("SIGTERM");
    } catch {}
  }
  setTimeout(() => {
    process.exit(0);
  }, 300);
}

process.on("SIGINT", cleanup);
process.on("SIGTERM", cleanup);
process.on("exit", cleanup);

backendProc.on("close", (code) => {
  if (code !== 0 && code !== null) {
    console.warn(`[backend] exited with code ${code}`);
  }
});

frontendProc.on("close", (code) => {
  if (code !== 0 && code !== null) {
    console.warn(`[frontend] exited with code ${code}`);
  }
});
