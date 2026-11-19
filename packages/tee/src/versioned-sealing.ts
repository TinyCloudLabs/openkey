import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

export type SealingBinding = {
  recordId: string;
  sealingContext: string;
};

export type SealingKeyProvider = (sealingContext: string, kid: number) => Promise<Uint8Array>;

const MAGIC = Buffer.from('OKSEAL\r\n', 'ascii');
const FORMAT_VERSION = 1;
const HEADER_LENGTH = 13;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

function parseBlob(blob: string, decoded?: Buffer): { bytes: Buffer; header: Buffer | undefined; kid: number } {
  if (blob.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(blob)) {
    throw new Error('Invalid sealed blob');
  }
  const bytes = decoded ?? Buffer.from(blob, 'base64');
  if (bytes.length < IV_LENGTH + TAG_LENGTH) {
    throw new Error('Invalid sealed blob');
  }
  if (!bytes.subarray(0, MAGIC.length).equals(MAGIC)) {
    return { bytes, header: undefined, kid: 0 };
  }
  if (bytes.length < HEADER_LENGTH + IV_LENGTH + TAG_LENGTH) {
    throw new Error('Invalid sealed blob');
  }
  if (bytes.readUInt8(MAGIC.length) !== FORMAT_VERSION) {
    throw new Error('Unsupported sealing format');
  }
  const kid = bytes.readUInt32BE(9);
  if (kid === 0) throw new Error('Invalid sealing key generation');
  return { bytes, header: bytes.subarray(0, HEADER_LENGTH), kid };
}

function authenticatedData(header: Buffer, binding: SealingBinding): Buffer {
  const recordLength = Buffer.byteLength(binding.recordId, 'utf8');
  const contextLength = Buffer.byteLength(binding.sealingContext, 'utf8');
  const aad = Buffer.allocUnsafe(HEADER_LENGTH + 8 + recordLength + contextLength);
  header.copy(aad);
  let offset = HEADER_LENGTH;
  aad.writeUInt32BE(recordLength, offset);
  offset += 4;
  aad.write(binding.recordId, offset, recordLength, 'utf8');
  offset += recordLength;
  aad.writeUInt32BE(contextLength, offset);
  offset += 4;
  aad.write(binding.sealingContext, offset, contextLength, 'utf8');
  return aad;
}

/** Returns the framing generation; it does not authenticate the blob. */
export function sealingKid(blob: string): number {
  return parseBlob(blob).kid;
}

/** Recognizes versioned framing; headerless validation remains with the legacy reader. */
export function isVersionedSealed(blob: string): boolean {
  const bytes = Buffer.from(blob, 'base64');
  if (!bytes.subarray(0, MAGIC.length).equals(MAGIC)) return false;
  parseBlob(blob, bytes);
  return true;
}

export class SealingKeyring {
  readonly writeKid: number;
  private readonly providers: ReadonlyMap<number, SealingKeyProvider>;

  constructor(options: { providers: ReadonlyMap<number, SealingKeyProvider>; writeKid?: number }) {
    this.writeKid = options.writeKid ?? 0;
    if (!Number.isInteger(this.writeKid) || this.writeKid < 0 || this.writeKid > 0xffffffff) {
      throw new Error('Invalid sealing key generation');
    }
    this.providers = options.providers;
  }

  private provider(kid: number): SealingKeyProvider {
    const provider = this.providers.get(kid);
    if (!provider) throw new Error('Unknown sealing key generation');
    return provider;
  }

  async seal(plaintext: string, binding: SealingBinding): Promise<string> {
    const provider = this.provider(this.writeKid);
    try {
      const key = await provider(binding.sealingContext, this.writeKid);
      const iv = randomBytes(IV_LENGTH);
      const cipher = createCipheriv('aes-256-gcm', key, iv);
      let header: Buffer | undefined;
      // Generation zero retains the headerless framing and has no AAD.
      if (this.writeKid !== 0) {
        header = Buffer.allocUnsafe(HEADER_LENGTH);
        MAGIC.copy(header);
        header.writeUInt8(FORMAT_VERSION, MAGIC.length);
        header.writeUInt32BE(this.writeKid, 9);
        cipher.setAAD(authenticatedData(header, binding));
      }
      const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
      const parts = [iv, cipher.getAuthTag(), ciphertext];
      if (header) parts.unshift(header);
      return Buffer.concat(parts).toString('base64');
    } catch {
      throw new Error('Unable to seal data');
    }
  }

  async unseal(blob: string, binding: SealingBinding): Promise<string> {
    const { bytes, header, kid } = parseBlob(blob);
    const provider = this.provider(kid);
    try {
      const key = await provider(binding.sealingContext, kid);
      const offset = header ? HEADER_LENGTH : 0;
      const decipher = createDecipheriv('aes-256-gcm', key, bytes.subarray(offset, offset + IV_LENGTH));
      if (header) decipher.setAAD(authenticatedData(header, binding));
      decipher.setAuthTag(bytes.subarray(offset + IV_LENGTH, offset + IV_LENGTH + TAG_LENGTH));
      const plaintext = Buffer.concat([
        decipher.update(bytes.subarray(offset + IV_LENGTH + TAG_LENGTH)),
        decipher.final(),
      ]);
      return plaintext.toString('utf8');
    } catch {
      throw new Error('Unable to unseal data');
    }
  }
}
