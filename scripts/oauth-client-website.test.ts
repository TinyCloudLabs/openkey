import { describe, expect, test } from 'bun:test';
import { updateWebsite } from './oauth-client-branding';

describe('updating the website of an existing OAuth client', () => {
  test('an empty or missing input keeps the stored website', () => {
    expect(updateWebsite({})).toEqual({});
    expect(updateWebsite({ CLIENT_URI: '' })).toEqual({});
    expect(updateWebsite({ CLIENT_URI: '   ' })).toEqual({});
    expect('uri' in updateWebsite({ CLIENT_URI: '' })).toBe(false);
  });

  test('an HTTPS URL replaces the stored website', () => {
    expect(updateWebsite({ CLIENT_URI: 'https://tinycloud.one' })).toEqual({ uri: 'https://tinycloud.one' });
    expect(updateWebsite({ CLIENT_URI: ' https://tinycloud.one/about ' })).toEqual({ uri: 'https://tinycloud.one/about' });
  });

  test('`none` clears the stored website, in any case and with spaces', () => {
    expect(updateWebsite({ CLIENT_URI: 'none' })).toEqual({ uri: null });
    expect(updateWebsite({ CLIENT_URI: ' None ' })).toEqual({ uri: null });
  });

  test('a value that is not an HTTPS URL is refused, not skipped', () => {
    for (const value of [
      'http://tinycloud.one',
      'http://localhost:5173',
      'javascript:alert(1)',
      'data:text/html,owned',
      'tinycloud.one',
      'https://user:pw@tinycloud.one',
      'https://tinycloud.one/#frag',
      'https://tiny cloud.one',
    ]) {
      expect(() => updateWebsite({ CLIENT_URI: value })).toThrow('CLIENT_URI must be an HTTPS URL');
    }
  });
});
