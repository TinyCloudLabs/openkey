// The email that carries the account setup code names the app that asked and the node the data goes to, as hosts only.
import { describe, expect, test } from 'bun:test';
import { mockModules } from './mock-module';

type Sent = { from: string; to: string; subject: string; text: string; html: string };
const sent: Sent[] = [];
process.env.RESEND_API_KEY = 're_test_key';
await mockModules({
  resend: () => ({
    Resend: class {
      emails = { send: async (mail: Sent) => { sent.push(mail); return { data: { id: 'mail_1' }, error: null }; } };
    },
  }),
});
const { accountSetupMail, sendAccountSetupCode } = await import('../services/account-setup-step-up?account-setup-step-up-mail' as string);

const NODE = 'https://node.tinycloud.xyz';
const body = (who: string, node: string, code = '123456') =>
  `${who} asked OpenKey to set up your TinyCloud account. Your data will be stored on ${node}.\n\n` +
  `Your code: ${code}\n\n` +
  "It expires in 5 minutes. Enter it only on openkey.so. If you didn't ask for this, don't share the code and ignore this email.";

describe('the setup code mail', () => {
  test('names the requesting app and the node by host', () => {
    const mail = accountSetupMail({ requestOrigin: 'https://app.example', nodeUrl: NODE, code: '123456' });
    expect(mail.subject).toBe('Your code to set up TinyCloud for app.example');
    expect(mail.text).toBe(body('app.example', 'node.tinycloud.xyz'));
    expect(mail.html).toBe(
      '<p>app.example asked OpenKey to set up your TinyCloud account. Your data will be stored on node.tinycloud.xyz.</p>' +
      '<p>Your code: 123456</p>' +
      '<p>It expires in 5 minutes. Enter it only on openkey.so. If you didn&#39;t ask for this, don&#39;t share the code and ignore this email.</p>',
    );
  });

  test.each([null, '', 'not a url', 'javascript:alert(1)'])('an empty or unparseable requester (%p) reads An app', (requestOrigin: string | null) => {
    const mail = accountSetupMail({ requestOrigin, nodeUrl: NODE, code: '654321' });
    expect(mail.subject).toBe('Your code to set up TinyCloud');
    expect(mail.text).toBe(body('An app', 'node.tinycloud.xyz', '654321'));
  });

  test('a node with a port keeps the port', () => {
    const mail = accountSetupMail({ requestOrigin: 'https://app.example:8443', nodeUrl: 'http://127.0.0.1:8000', code: '123456' });
    expect(mail.subject).toBe('Your code to set up TinyCloud for app.example:8443');
    expect(mail.text).toBe(body('app.example:8443', '127.0.0.1:8000'));
  });

  test('a URL with a path, query or credentials gives the host only', () => {
    const mail = accountSetupMail({
      requestOrigin: 'https://user:secret@app.example/some/path?token=abc#frag', nodeUrl: 'https://node.tinycloud.xyz/v1/info?x=1', code: '123456',
    });
    expect(mail.subject).toBe('Your code to set up TinyCloud for app.example');
    expect(mail.text).toBe(body('app.example', 'node.tinycloud.xyz'));
    expect(`${mail.subject}${mail.text}${mail.html}`).not.toMatch(/https?:|secret|token|some\/path|v1\/info/);
  });

  test('a host that carries markup is escaped in the html', () => {
    const mail = accountSetupMail({ requestOrigin: 'foo://a<b>&c', nodeUrl: NODE, code: '123456' });
    expect(mail.html).not.toContain('<b>');
  });

  test('without a readable node no code is made and nothing is mailed', async () => {
    let writes = 0;
    const db = { $transaction: async () => { writes += 1; return true; }, verification: { deleteMany: async () => {} } };
    expect(await sendAccountSetupCode(db, { sessionId: 's', requestId: 'r', email: 'o@example.test', requestOrigin: 'https://app.example', nodeUrl: 'nope' }))
      .toBe('unavailable');
    expect(writes).toBe(0);
    expect(sent).toEqual([]);
  });

  test('is the mail Resend is given, from OpenKey, to the owner, with the code stored only as its digest', async () => {
    const stored: unknown[] = [];
    const tx = {
      $queryRaw: async () => [],
      verification: {
        findFirst: async () => null, deleteMany: async () => {},
        create: async (args: { data: unknown }) => { stored.push(args.data); },
      },
    };
    const db = { $transaction: async (run: (client: typeof tx) => unknown) => run(tx), verification: { deleteMany: async () => {} } };
    const result = await sendAccountSetupCode(db, {
      sessionId: 'session-1', requestId: 'req-1', email: 'owner@example.test', requestOrigin: 'https://app.example', nodeUrl: NODE,
    });
    expect(result).toBe('sent');
    expect(sent).toHaveLength(1);
    const mail = sent[0]!;
    expect(mail.from).toBe('OpenKey <noreply@openkey.so>');
    expect(mail.to).toBe('owner@example.test');
    expect(mail.subject).toBe('Your code to set up TinyCloud for app.example');
    const code = /Your code: (\d{6})/.exec(mail.text)![1]!;
    expect(mail.text).toBe(body('app.example', 'node.tinycloud.xyz', code));
    expect(JSON.stringify(stored)).not.toContain(code);
  });
});
