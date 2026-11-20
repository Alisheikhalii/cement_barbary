import { pathToFileURL } from 'node:url';

import { loadEnvFiles } from '../config/load-env.js';
import { runCreateUser } from './operator-cli.js';

/**
 * Entry point for `create-user` (F1-04 T08). Thin wrapper only: the logic
 * lives in operator-cli.ts so production guards and flags are testable without
 * a process. Loads .env files (never overriding the real environment), runs,
 * and exits with the command's status code.
 */
async function main(): Promise<void> {
  loadEnvFiles();
  const code = await runCreateUser(process.argv.slice(2), {
    io: {
      out: (line) => process.stdout.write(line + '\n'),
      err: (line) => process.stderr.write(line + '\n'),
    },
    env: process.env,
  });
  // exitCode (not exit()) lets buffered stdout—the only copy of the
  // password—flush before the process ends.
  process.exitCode = code;
}

const invokedAsCli = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedAsCli) {
  void main();
}
