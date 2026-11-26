// The sign pop-up's flow id for one document: a carried id is read once and every page instance created in the same
// document uses it; a new document draws or reads its own.
// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { newWebSignFlowId } from './web-sign-flow';

const SHAPE = /^w\.[A-Za-z0-9_-]{32}$/;
const KEY = 'openkey_sign_flow';

function memoryStorage(initial: Record<string, string> = {}) {
  const values = new Map(Object.entries(initial));
  return {
    values,
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); },
    removeItem: (key: string) => { values.delete(key); },
  };
}

// A module import with its own query is a module instance of its own: a second document.
const newDocument = async (n: number) => (await import(`./web-sign-flow?document=${n}`)) as typeof import('./web-sign-flow');

describe('the pop-up flow id of a document', () => {
  test('a carried id is returned once from storage and reused for every call in the document', async () => {
    const doc = await newDocument(1);
    const storage = memoryStorage();
    const carried = newWebSignFlowId();
    doc.carryPopupSignFlow(carried, storage);

    expect(doc.popupSignFlowId(storage)).toBe(carried);
    expect(storage.values.has(KEY)).toBe(false);
    expect(doc.popupSignFlowId(storage)).toBe(carried);
    expect(doc.popupSignFlowId(storage)).toBe(carried);
  });

  test('with nothing carried one new id is drawn and reused', async () => {
    const doc = await newDocument(2);
    const storage = memoryStorage();
    const first = doc.popupSignFlowId(storage);
    expect(first).toMatch(SHAPE);
    expect(doc.popupSignFlowId(storage)).toBe(first);
    expect(doc.popupSignFlowId(storage)).toBe(first);
  });

  test('a second document draws a new id when nothing is carried and reads its own carried id', async () => {
    const first = await newDocument(3);
    const second = await newDocument(4);
    const drawn = first.popupSignFlowId(memoryStorage());
    expect(second.popupSignFlowId(memoryStorage())).not.toBe(drawn);

    const third = await newDocument(5);
    const carried = newWebSignFlowId();
    expect(third.popupSignFlowId(memoryStorage({ [KEY]: carried }))).toBe(carried);
  });

  test('a stored value without the web shape is ignored', async () => {
    const doc = await newDocument(6);
    const storage = memoryStorage({ [KEY]: 'not-a-flow' });
    const id = doc.popupSignFlowId(storage);
    expect(id).toMatch(SHAPE);
    expect(id).not.toBe('not-a-flow');
    expect(storage.values.has(KEY)).toBe(false);
  });

  test('a forgotten id is replaced by a new one for the next request', async () => {
    const doc = await newDocument(7);
    const storage = memoryStorage();
    const first = doc.popupSignFlowId(storage);
    doc.forgetPopupSignFlow();
    expect(doc.popupSignFlowId(storage)).not.toBe(first);
  });
});
