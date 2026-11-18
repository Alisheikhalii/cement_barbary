import { resolve } from 'node:path';

/**
 * Loads .env files if they exist (they are never committed — see .gitignore).
 * Variables already present in the environment are not overridden.
 * Missing files are fine: values may come from the shell or Docker Compose.
 */
export function loadEnvFiles(cwd: string = process.cwd()): void {
  for (const path of [resolve(cwd, '.env'), resolve(cwd, '../../.env')]) {
    try {
      process.loadEnvFile(path);
    } catch {
      // File missing or unreadable — not an error.
    }
  }
}
