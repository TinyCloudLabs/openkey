import type { PageLoad } from './$types';

export const load: PageLoad = ({ url }) => {
	return {
		initialStep: (url.searchParams.get('step') as 'email' | 'otp' | 'passkey') || 'email',
		isEmbed: url.searchParams.has('embed')
	};
};
