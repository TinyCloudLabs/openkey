/// <reference types="@sveltejs/kit" />

declare global {
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
