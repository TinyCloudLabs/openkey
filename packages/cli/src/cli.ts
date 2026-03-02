import { Command } from 'commander';
import { loginCommand } from './commands/login';
import { logoutCommand } from './commands/logout';
import { whoamiCommand } from './commands/whoami';
import { keysCommand } from './commands/keys';
import { signCommand } from './commands/sign';
import { tokenCommand } from './commands/token';
import { OpenKeyError } from '@openkey/core';

const DEFAULT_HOST = 'https://openkey.so';

const program = new Command();

program
  .name('openkey')
  .description('CLI tool for authenticating with OpenKey')
  .version('0.0.1')
  .option('--host <url>', 'OpenKey host URL', DEFAULT_HOST)
  .option('--client-id <id>', 'OAuth client ID');

program
  .command('login')
  .description('Authenticate with OpenKey')
  .option('--no-browser', 'Print URL instead of opening browser')
  .action(async (opts) => {
    const { host, clientId } = program.opts();
    if (!clientId) {
      console.error('Error: --client-id is required. Register an OAuth client first.');
      process.exit(1);
    }
    await loginCommand({ host, clientId, noBrowser: opts.browser === false });
  });

program
  .command('logout')
  .description('Revoke tokens and clear stored credentials')
  .action(async () => {
    const { host } = program.opts();
    await logoutCommand({ host });
  });

program
  .command('whoami')
  .description('Show current user info')
  .action(async () => {
    const { host, clientId } = program.opts();
    if (!clientId) {
      console.error('Error: --client-id is required.');
      process.exit(1);
    }
    await whoamiCommand({ host, clientId });
  });

program
  .command('keys')
  .description('List your keys')
  .action(async () => {
    const { host, clientId } = program.opts();
    if (!clientId) {
      console.error('Error: --client-id is required.');
      process.exit(1);
    }
    await keysCommand({ host, clientId });
  });

program
  .command('sign <message>')
  .description('Sign a message with a managed key')
  .option('--key-id <id>', 'Key ID to sign with (defaults to first managed key)')
  .action(async (message: string, opts) => {
    const { host, clientId } = program.opts();
    if (!clientId) {
      console.error('Error: --client-id is required.');
      process.exit(1);
    }
    await signCommand(message, { host, clientId, keyId: opts.keyId });
  });

program
  .command('token')
  .description('Print current access token (for piping to other tools)')
  .action(async () => {
    const { host, clientId } = program.opts();
    if (!clientId) {
      console.error('Error: --client-id is required.');
      process.exit(1);
    }
    await tokenCommand({ host, clientId });
  });

// Global error handler
program.hook('postAction', () => {});

async function main() {
  try {
    await program.parseAsync();
  } catch (err) {
    if (err instanceof OpenKeyError) {
      console.error(`Error [${err.code}]: ${err.message}`);
    } else if (err instanceof Error) {
      console.error(`Error: ${err.message}`);
    } else {
      console.error('An unknown error occurred');
    }
    process.exit(1);
  }
}

main();
