// Sign-out endpoint - clears session cookies
import { redirect } from '@sveltejs/kit';
import type { RequestHandler } from './$types';

export const POST: RequestHandler = async ({ cookies }) => {
  cookies.delete('admin_session', { path: '/' });
  cookies.delete('admin_refresh_token', { path: '/' });
  throw redirect(302, '/login');
};
