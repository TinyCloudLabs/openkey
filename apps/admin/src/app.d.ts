// See https://svelte.dev/docs/kit/types#app.d.ts
// for information about these interfaces
declare global {
	namespace App {
		// interface Error {}
		interface Locals {
			user: {
				id: string;
				email: string;
				name?: string | null;
			} | null;
			session: {
				id: string;
				token: string;
			} | null;
			developerAccount: {
				id: string;
				plan: string;
				billingState: string;
				mauLimit: number;
				appLimit: number;
				stripeCustomerId: string | null;
				stripeSubscriptionId: string | null;
			} | null;
		}
		// interface PageData {}
		// interface PageState {}
		// interface Platform {}
	}
}

export {};
