import { writeFile } from 'node:fs/promises';
import { runPrismaGenerateCli, withPrismaGenerateLock } from './generate-prisma';

if (process.argv[2] === '--cli-test') {
  const [, , , lockPath, markerDirectory, workerId, operationMs] = process.argv;
  if (!lockPath || !markerDirectory || !workerId || !operationMs) {
    throw new Error('CLI test worker arguments are required');
  }

  await runPrismaGenerateCli({
    args: ['--then', 'test-consumer'],
    lockOptions: { lockPath, pollMs: 2, staleLockMs: 500, heartbeatMs: 25 },
    generate: async () => {
      await writeFile(`${markerDirectory}/${workerId}.generated`, String(Date.now()));
    },
    runCommand: async () => {
      await writeFile(`${markerDirectory}/${workerId}.consumer`, String(Date.now()));
      await new Promise((resolve) => setTimeout(resolve, Number(operationMs)));
      return 0;
    },
  });
} else {
  const [lockPath, markerDirectory, workerId, operationMs, staleLockMs, heartbeatMs] = process.argv.slice(2);

  if (!lockPath || !markerDirectory || !workerId || !operationMs || !staleLockMs || !heartbeatMs) {
    throw new Error('worker arguments are required');
  }

  const startPath = `${markerDirectory}/${workerId}.start`;
  const endPath = `${markerDirectory}/${workerId}.end`;

  await withPrismaGenerateLock(async () => {
    await writeFile(startPath, String(Date.now()));
    await new Promise((resolve) => setTimeout(resolve, Number(operationMs)));
    await writeFile(endPath, String(Date.now()));
  }, {
    lockPath,
    pollMs: 2,
    staleLockMs: Number(staleLockMs),
    heartbeatMs: Number(heartbeatMs),
  });
}
