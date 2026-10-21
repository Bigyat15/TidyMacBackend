import { openDb } from "../src/db.ts";
import { prune } from "../src/maintenance.ts";

const path = process.env.DATABASE_PATH;
if (!path || path === ":memory:") { console.error("Set DATABASE_PATH to the licensing database file."); process.exit(2); }
console.log("pruned:", prune(openDb(path), Math.floor(Date.now() / 1000)));
