import { normalizeRegisterReturnTo } from '../../../lib/auth-flow';

import type { PageLoad } from './$types';

export const load: PageLoad = ({ url }) => {
	const returnTo = url.searchParams.get('returnTo');

	return {
		initialStep: (url.searchParams.get('step') as 'email' | 'otp' | 'passkey') || 'email',
		isEmbed: url.searchParams.has('embed'),
		returnTo: normalizeRegisterReturnTo(returnTo, url.origin)
	};
};
