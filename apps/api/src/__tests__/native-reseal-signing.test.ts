import { expect, test } from 'bun:test';

for (const operation of ['consent', 'renewal']) {
  for (const corrupt of [false, true]) {
    test(`${operation} reopens a drifted sealed row ${corrupt ? 'and refuses corrupt data without signing' : 'without rejecting an unchanged identity'}`, async () => {
      const child = Bun.spawn([process.execPath, new URL('./fixtures/native-reseal-scenario.ts', import.meta.url).pathname, operation, corrupt ? 'corrupt' : 'valid'], {
        stdout: 'pipe', stderr: 'pipe',
      });
      const [stdout, , exit] = await Promise.all([new Response(child.stdout).text(), new Response(child.stderr).text(), child.exited]);
      if (exit !== 0) throw new Error('Native maintenance scenario failed before reporting');
      const result: unknown = JSON.parse(stdout.trim().split('\n').at(-1)!);
      expect(result).toEqual({ status: corrupt ? 500 : 200, signatureValid: !corrupt, freshOpen: true });
    });
  }
}
