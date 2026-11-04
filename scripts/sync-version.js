// Runs from `npm version`: copies the new package.json version into server.json.
import { readFileSync, writeFileSync } from "node:fs";
const { version } = JSON.parse(readFileSync("package.json", "utf8"));
const server = JSON.parse(readFileSync("server.json", "utf8"));
server.version = version;
for (const p of server.packages) p.version = version;
writeFileSync("server.json", JSON.stringify(server, null, 2) + "\n");
