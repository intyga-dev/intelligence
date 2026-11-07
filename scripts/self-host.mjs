import { initialiseSelfHost } from "../src/selfhost/setup.ts"

const args = process.argv.slice(2)
if (args.includes("--help")) {
  console.log("Usage: node scripts/self-host.mjs [--origin https://intelligence.example.com] [--port 4100]")
  process.exit(0)
}
let origin
let port = 4100
for (let i = 0; i < args.length; i += 2) {
  if (args[i] === "--origin" && args[i + 1]) origin = args[i + 1]
  else if (args[i] === "--port" && args[i + 1]) port = Number(args[i + 1])
  else throw new Error("Unknown or incomplete option. Run with --help.")
}
origin ??= `http://localhost:${port}`
initialiseSelfHost(process.cwd(), origin, port)
console.log(`Created .env.selfhost with new installation secrets.
Start the stack:
  docker compose --env-file .env.selfhost -f compose.selfhost.yml up -d --build

Open ${origin}. For HTTPS, first configure your reverse proxy to forward to 127.0.0.1:${port}.
The setup form needs SETUP_TOKEN from .env.selfhost, plus three things from your INTYGA console:
an App sign-in client id, a service key and the exported trust anchor.
See docs/SELF_HOST.md for the full walkthrough, upgrades and backups.`)
