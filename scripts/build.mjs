import { cp, mkdir } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const dist = resolve(root, "dist");

await mkdir(dist, { recursive: true });
await cp(resolve(root, "src", "index.js"), resolve(dist, "index.js"));
await cp(resolve(root, "src", "index.d.ts"), resolve(dist, "index.d.ts"));
await cp(resolve(root, "src", "cli.mjs"), resolve(dist, "cli.mjs"));
