import { redirect } from '@sveltejs/kit';
import type { PageServerLoad } from './$types';
import { db } from '$lib/server/db';

export const load: PageServerLoad = async ({ locals }) => {
	const user = locals.user;
	if (!user) throw redirect(302, '/');

	const apps = await db.oauthClient.findMany({
		where: { userId: user.id },
		orderBy: { createdAt: 'desc' },
		select: {
			id: true,
			clientId: true,
			name: true,
			uri: true,
			icon: true,
			type: true,
			disabled: true,
			createdAt: true,
		},
	});

	return { apps };
};
