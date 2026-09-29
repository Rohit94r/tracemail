#!/usr/bin/env node

/**
 * Raven (SecureMailScope) — Monorepo Setup Script
 * Installs all workspace node_modules and verifies/installs Python dependencies.
 */

import { spawnSync } from "child_process";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PLATFORM_DIR = path.resolve(__dirname, "..");

console.log("\x1b[36m%s\x1b[0m", "\n🦅 Raven (SecureMailScope) Setup\n==========================================");

// 1. Install Node.js dependencies
console.log("\x1b[33m%s\x1b[0m", "[1/3] Installing frontend dependencies via pnpm...");
const pnpmResult = spawnSync("pnpm", ["install"], {
  cwd: PLATFORM_DIR,
  stdio: "inherit",
});

if (pnpmResult.error || pnpmResult.status !== 0) {
  console.error("\x1b[31m%s\x1b[0m", "Failed to run pnpm install");
  process.exit(1);
}

// 2. Check and install Python dependencies
console.log("\x1b[33m%s\x1b[0m", "\n[2/3] Checking Python 3 dependencies...");
const pyCheck = spawnSync(
  "python3",
  ["-c", "import fastapi, uvicorn, scapy, cryptography, pydantic, pymongo, dns"],
  { cwd: PLATFORM_DIR }
);

if (pyCheck.status !== 0) {
  console.log("\x1b[33m%s\x1b[0m", "Installing missing Python dependencies from backend/requirements.txt...");
  const pipResult = spawnSync(
    "python3",
    ["-m", "pip", "install", "-r", "backend/requirements.txt"],
    { cwd: PLATFORM_DIR, stdio: "inherit" }
  );
  if (pipResult.error || pipResult.status !== 0) {
    console.warn("\x1b[31m%s\x1b[0m", "Warning: Failed to install Python dependencies via pip.");
  }
} else {
  console.log("\x1b[32m%s\x1b[0m", "✓ Python dependencies verified (fastapi, scapy, cryptography, uvicorn, pydantic, pymongo)");
}

// 3. Initialize MongoDB Atlas database connection and indices
console.log("\x1b[33m%s\x1b[0m", "\n[3/3] Initializing MongoDB Atlas forensic evidence collections...");
spawnSync(
  "python3",
  ["-c", "from backend.app.db import init_db; init_db(); print('✓ MongoDB Atlas initialized')"],
  { cwd: PLATFORM_DIR, env: { ...process.env, PYTHONPATH: PLATFORM_DIR }, stdio: "inherit" }
);

console.log("\x1b[32m%s\x1b[0m", "\n✨ Setup Complete! Run 'pnpm dev' to launch both backend and frontend together.\n");
