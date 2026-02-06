/// <reference types="@sveltejs/kit" />

interface EthereumProvider {
  request(args: { method: 'eth_requestAccounts' }): Promise<string[]>;
  request(args: { method: 'personal_sign'; params: [string, string] }): Promise<string>;
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

declare global {
  interface Window {
    ethereum?: EthereumProvider;
  }

  namespace App {
    interface Locals {
      user: {
        id: string;
        email: string;
        name?: string;
      } | null;
      session: {
        id: string;
        expiresAt: Date;
      } | null;
    }
    // interface Error {}
    // interface PageData {}
    // interface PageState {}
    // interface Platform {}
  }
}

export {};
