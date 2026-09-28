import { cpSync, existsSync, rmSync } from "node:fs";
import { resolve } from "node:path";

const source = resolve("dist");
const destination = resolve("../src/arbiter/dashboard");

if (!existsSync(resolve(source, "index.html"))) {
  throw new Error("Build the dashboard before syncing it: npm run build");
}

rmSync(destination, { force: true, recursive: true });
cpSync(source, destination, { recursive: true });
