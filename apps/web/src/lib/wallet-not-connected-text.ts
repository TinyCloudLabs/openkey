export function walletNotConnectedText(expectedShort: string, email: string | null): string {
  const who = email ? `You're signed in as ${email}, and none of your keys is for that wallet.` : 'None of your keys is for that wallet.';
  return `This request is for wallet ${expectedShort}. ${who} Sign in with the account that owns it, or link the wallet below.`;
}
