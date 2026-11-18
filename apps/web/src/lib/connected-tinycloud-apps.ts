// Disconnecting a TinyCloud signing app: in Settings, and on the ways-out page reached from the Terms.
export const tinyCloudDisconnectCopy = {
  confirmation: 'DISCONNECT',
  disconnect: 'Disconnect',
  empty: 'No connected apps can request TinyCloud signatures.',
  title: (name: string) => `Disconnect ${name}`,
  body: 'This withdraws the app’s OAuth consent and revokes its device grants and tokens. Already issued delegations remain usable until they expire.',
  typeToConfirm: 'Type DISCONNECT to confirm',
  sessionNote: 'This change is authorized by your signed-in OpenKey session. Passkeys remain available as optional account protection.',
  cancel: 'Cancel',
  action: 'Disconnect app',
  failed: 'Failed to disconnect TinyCloud app',
} as const;
