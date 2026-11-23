import { describe, expect, test } from 'bun:test';
import { classifyDelegateLinkDelivery, isLoopbackCallback } from '../services/delegate-link-delivery';

describe('loopback callback', () => {
  test('http://127.0.0.1:PORT/x is loopback', () => {
    expect(isLoopbackCallback('http://127.0.0.1:43111/x')).toBe(true);
  });
  test('http://localhost:PORT is loopback', () => {
    expect(isLoopbackCallback('http://localhost:43111')).toBe(true);
  });
  test('http://[::1]:PORT is loopback', () => {
    expect(isLoopbackCallback('http://[::1]:43111')).toBe(true);
  });
  test('127.0.0.1.evil.com is third-party', () => {
    expect(isLoopbackCallback('http://127.0.0.1.evil.com:43111/x')).toBe(false);
  });
  test('localhost.evil.com is third-party', () => {
    expect(isLoopbackCallback('http://localhost.evil.com:43111/x')).toBe(false);
  });
  test('0.0.0.0 is third-party', () => {
    expect(isLoopbackCallback('http://0.0.0.0:43111/x')).toBe(false);
  });
  test('the decimal IP 2130706433 is third-party', () => {
    expect(isLoopbackCallback('http://2130706433:43111/x')).toBe(false);
  });
  test('the octal IP 0177.0.0.1 is third-party', () => {
    expect(isLoopbackCallback('http://0177.0.0.1:43111/x')).toBe(false);
  });
  test('the hex IP 0x7f.0.0.1 is third-party', () => {
    expect(isLoopbackCallback('http://0x7f.0.0.1:43111/x')).toBe(false);
  });
  test('http://127.0.0.1@evil.example is third-party', () => {
    expect(isLoopbackCallback('http://127.0.0.1@evil.example')).toBe(false);
  });
  test('user info in front of a loopback host is third-party', () => {
    expect(isLoopbackCallback('http://user@127.0.0.1:43111/x')).toBe(false);
  });
  test('https://127.0.0.1:PORT (wrong scheme) is third-party', () => {
    expect(isLoopbackCallback('https://127.0.0.1:43111/x')).toBe(false);
  });
  test('a loopback host with no explicit port is third-party', () => {
    expect(isLoopbackCallback('http://127.0.0.1/x')).toBe(false);
  });
  test('a port the URL parser drops (80) is third-party', () => {
    expect(isLoopbackCallback('http://127.0.0.1:80/x')).toBe(false);
  });
  test('a port out of range is third-party', () => {
    expect(isLoopbackCallback('http://127.0.0.1:70000/x')).toBe(false);
  });
  test('https://evil.example is third-party', () => {
    expect(isLoopbackCallback('https://evil.example')).toBe(false);
  });
  test('http://user@evil.example\\@127.0.0.1 is third-party', () => {
    expect(isLoopbackCallback('http://user@evil.example\\@127.0.0.1')).toBe(false);
  });
  test('a backslash after the port is third-party', () => {
    expect(isLoopbackCallback('http://127.0.0.1:43111\\@evil.example')).toBe(false);
  });
  test('an upper-case or padded host is third-party', () => {
    expect(isLoopbackCallback('http://LOCALHOST:43111')).toBe(false);
    expect(isLoopbackCallback(' http://127.0.0.1:43111')).toBe(false);
  });
  test('a non-string is third-party', () => {
    expect(isLoopbackCallback(undefined)).toBe(false);
    expect(isLoopbackCallback(43111)).toBe(false);
    expect(isLoopbackCallback(['http://127.0.0.1:43111'])).toBe(false);
  });
});

describe('link delivery', () => {
  test('a link that sent the paste kind and no callback is paste', () => {
    expect(classifyDelegateLinkDelivery('paste', undefined)).toBe('paste');
  });
  test('the paste kind with a callback is not recognised', () => {
    expect(classifyDelegateLinkDelivery('paste', 'https://evil.example')).toBeUndefined();
  });
  test('a missing kind is not paste, with or without a callback', () => {
    expect(classifyDelegateLinkDelivery(undefined, undefined)).toBeUndefined();
    expect(classifyDelegateLinkDelivery(undefined, 'http://127.0.0.1:43111')).toBeUndefined();
  });
  test('the callback kind counts only for a loopback callback', () => {
    expect(classifyDelegateLinkDelivery('callback', 'http://127.0.0.1:43111/x')).toBe('loopback');
    expect(classifyDelegateLinkDelivery('callback', 'https://app.example/cb')).toBeUndefined();
    expect(classifyDelegateLinkDelivery('callback', undefined)).toBeUndefined();
  });
  test('an unknown kind is not recognised', () => {
    expect(classifyDelegateLinkDelivery('loopback', 'http://127.0.0.1:43111')).toBeUndefined();
  });
});
