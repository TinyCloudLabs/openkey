import type { PageLoad } from './$types';

export const load: PageLoad = ({ url }) => {
	const returnTo = url.searchParams.get('returnTo');

	return {
		initialStep: (url.searchParams.get('step') as 'email' | 'otp' | 'passkey') || 'email',
		isEmbed: url.searchParams.has('embed'),
		returnTo: normalizeDelegateReturnTo(returnTo, url.origin)
	};
};

function normalizeDelegateReturnTo(returnTo: string | null, origin: string) {
	if (!returnTo) return null;

	try {
		const returnUrl = new URL(returnTo, origin);
		if (returnUrl.origin !== origin || returnUrl.pathname !== '/delegate') return null;
		return returnUrl.pathname + returnUrl.search + returnUrl.hash;
	} catch {
		return null;
	}
}
