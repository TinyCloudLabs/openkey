export type RegisteredDeletionHost = { hostId: string; url: string };
export type OwnerSpacePage = {
  version: number; hostId: string; ownerDid: string; spaces: string[];
  nextCursor: string | null; lastPage: boolean;
};

/** The transport must use TLS certificate validation and refuse redirects. */
export async function listAllDeletionSpaces(
  host: RegisteredDeletionHost,
  ownerDid: string,
  request: (url: string, body: { version: 1; ownerDid: string; cursor: string | null }) => Promise<OwnerSpacePage>,
): Promise<string[]> {
  const url = new URL(host.url);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) {
    throw new Error('Invalid registered host TLS origin');
  }
  if (!host.hostId) throw new Error('Missing registered host identity');
  const spaces: string[] = [];
  const cursors = new Set<string>();
  let cursor: string | null = null;
  for (;;) {
    const page = await request(new URL('/space/list', url).href, { version: 1, ownerDid, cursor });
    if (page.version !== 1 || page.hostId !== host.hostId || page.ownerDid !== ownerDid || !Array.isArray(page.spaces) || page.spaces.length > 500 || typeof page.lastPage !== 'boolean') {
      throw new Error('Incomplete or mismatched owner space listing');
    }
    for (const space of page.spaces) {
      if (typeof space !== 'string' || !space.startsWith('tinycloud:') || (spaces.length > 0 && space <= spaces[spaces.length - 1]!)) {
        throw new Error('Invalid owner space ordering');
      }
      spaces.push(space);
    }
    if (page.lastPage) {
      if (page.nextCursor !== null) throw new Error('Invalid terminal page');
      return spaces;
    }
    if (typeof page.nextCursor !== 'string' || !page.nextCursor || cursors.has(page.nextCursor)) throw new Error('Incomplete owner space pagination');
    cursors.add(page.nextCursor);
    cursor = page.nextCursor;
  }
}
