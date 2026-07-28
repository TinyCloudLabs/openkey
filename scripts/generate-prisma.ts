#!/usr/bin/env bun

import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readdir, rename, rm, rmdir, stat, unlink, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const repoRoot = resolve(import.meta.dir, '..');
const schemaPath = join(repoRoot, 'packages/db/prisma/schema.prisma');
const prismaBin = join(repoRoot, 'node_modules/.bin/prisma');
const defaultLockPath = join(
  tmpdir(),
  `openkey-build-tooling-${createHash('sha256').update(repoRoot).digest('hex').slice(0, 16)}.lock`,
);

const DEFAULT_STALE_LOCK_MS = 60 * 1000;
const DEFAULT_POLL_MS = 100;
const LOCK_HELD_ENV = 'OPENKEY_BUILD_TOOLING_LOCK';

type LockOwner = {
  pid: number;
  token: string;
};

export type PrismaGenerateLockOptions = {
  lockPath?: string;
  pollMs?: number;
  staleLockMs?: number;
  heartbeatMs?: number;
};

type CommandRunner = (command: string, args: string[]) => Promise<number>;

export type PrismaGenerateCliOptions = {
  args?: string[];
  env?: NodeJS.ProcessEnv;
  generate?: () => Promise<void>;
  lockOptions?: PrismaGenerateLockOptions;
  runCommand?: CommandRunner;
};

function delay(milliseconds: number) {
  return new Promise<void>((resolveDelay) => setTimeout(resolveDelay, milliseconds));
}

async function lockAgeMs(lockPath: string) {
  try {
    const files = await readdir(lockPath);
    const leaseFile = files.find((file) => file.startsWith('lease-') && file.endsWith('.json')) ?? 'lease';
    const leaseStats = await stat(join(lockPath, leaseFile));
    return Date.now() - leaseStats.mtimeMs;
  } catch {
    try {
      const lockStats = await stat(lockPath);
      return Date.now() - lockStats.mtimeMs;
    } catch {
      return undefined;
    }
  }
}

async function removeAbandonedLock(lockPath: string, staleLockMs: number) {
  const ageMs = await lockAgeMs(lockPath);
  if (ageMs === undefined) {
    return true;
  }

  if (ageMs < staleLockMs) {
    return false;
  }

  const quarantinePath = `${lockPath}.stale-${randomUUID()}`;
  try {
    await rename(lockPath, quarantinePath);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') {
      return true;
    }
    if (code === 'ENOTEMPTY' || code === 'EEXIST') {
      return false;
    }
    throw error;
  }

  // Renaming first prevents this cleanup from ever deleting a lock acquired
  // after the stale lock was displaced.
  await rm(quarantinePath, { recursive: true, force: true });
  return true;
}

function startHeartbeat(lockPath: string, leasePath: string, heartbeatMs: number) {
  const heartbeat = setInterval(() => {
    const now = new Date();
    utimes(leasePath, now, now).catch(() => {
      // The lock may have been atomically quarantined by a stale waiter.
    });
  }, heartbeatMs);
  heartbeat.unref?.();
  return heartbeat;
}

export async function withPrismaGenerateLock<T>(
  operation: () => T | Promise<T>,
  options: PrismaGenerateLockOptions = {},
): Promise<T> {
  const lockPath = options.lockPath ?? defaultLockPath;
  const pollMs = options.pollMs ?? DEFAULT_POLL_MS;
  const staleLockMs = options.staleLockMs ?? DEFAULT_STALE_LOCK_MS;
  const heartbeatMs = options.heartbeatMs ?? Math.max(1, Math.floor(staleLockMs / 3));
  const owner: LockOwner = { pid: process.pid, token: randomUUID() };
  const candidatePath = `${lockPath}.candidate-${owner.token}`;
  const ownerPath = join(lockPath, `owner-${owner.token}.json`);
  const leasePath = join(lockPath, `lease-${owner.token}.json`);

  while (true) {
    try {
      await mkdir(candidatePath);
      await writeFile(join(candidatePath, `owner-${owner.token}.json`), JSON.stringify(owner));
      await writeFile(join(candidatePath, `lease-${owner.token}.json`), 'lease');
      await rename(candidatePath, lockPath);
      break;
    } catch (error) {
      await rm(candidatePath, { recursive: true, force: true });
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
        if ((error as NodeJS.ErrnoException).code !== 'ENOTEMPTY') {
          throw error;
        }
      }
      if (!await removeAbandonedLock(lockPath, staleLockMs)) {
        await delay(pollMs);
      }
    }
  }

  const heartbeat = startHeartbeat(lockPath, leasePath, heartbeatMs);
  const previousLockEnv = process.env[LOCK_HELD_ENV];
  process.env[LOCK_HELD_ENV] = owner.token;
  try {
    return await operation();
  } finally {
    clearInterval(heartbeat);
    if (previousLockEnv === undefined) {
      delete process.env[LOCK_HELD_ENV];
    } else {
      process.env[LOCK_HELD_ENV] = previousLockEnv;
    }

    // Remove only uniquely-owned files. A stale waiter may have renamed this
    // directory, or a replacement owner may already hold the original path.
    await unlink(ownerPath).catch(() => undefined);
    await unlink(leasePath).catch(() => undefined);
    await rmdir(lockPath).catch(() => undefined);
  }
}

function runCommand(command: string, args: string[]) {
  return new Promise<number>((resolveCommand, rejectCommand) => {
    const child = spawn(command, args, {
      cwd: process.cwd(),
      env: process.env,
      stdio: 'inherit',
    });
    child.once('error', rejectCommand);
    child.once('close', (code, signal) => {
      if (signal) {
        rejectCommand(new Error(`${command} was terminated by ${signal}`));
      } else {
        resolveCommand(code ?? 1);
      }
    });
  });
}

async function runCommandOrThrow(command: string, args: string[], commandRunner: CommandRunner = runCommand) {
  const status = await commandRunner(command, args);
  if (status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed with exit code ${status}`);
  }
}

export async function runPrismaGenerateCli(options: PrismaGenerateCliOptions = {}) {
  const args = options.args ?? process.argv.slice(2);
  const env = options.env ?? process.env;
  const thenIndex = args.indexOf('--then');
  const command = thenIndex === -1 ? undefined : args.slice(thenIndex + 1);

  if (thenIndex !== -1 && (!command || command.length === 0)) {
    throw new Error('--then requires a command');
  }

  const inheritedLock = Boolean(env[LOCK_HELD_ENV]);
  const generate = options.generate ?? generatePrismaClient;
  const commandRunner = options.runCommand ?? runCommand;
  const operation = async () => {
    if (!inheritedLock) {
      await generate();
    }
    if (command) {
      await runCommandOrThrow(command[0], command.slice(1), commandRunner);
    }
  };

  if (inheritedLock) {
    await operation();
  } else {
    await withPrismaGenerateLock(operation, options.lockOptions);
  }
}

async function runCli() {
  await runPrismaGenerateCli();
}

export async function generatePrismaClient() {
  await runCommandOrThrow(process.execPath, [prismaBin, 'generate', '--schema', schemaPath]);
}

if (import.meta.main) {
  runCli().catch((error) => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
  });
}
