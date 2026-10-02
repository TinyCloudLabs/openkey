import type { RequestHandler } from './$types';
import { applicationReadCapabilitiesResponse } from '$lib/app-read-discovery';

// Use the exact API origin configured for /delegate. Static assets cannot
// establish that the deployed signing API supports the required protocol.
export const GET: RequestHandler = ({ fetch }) =>
  applicationReadCapabilitiesResponse(fetch, import.meta.env.VITE_API_URL || '');
