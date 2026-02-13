import type { PageServerLoad } from './$types';

export const load: PageServerLoad = async ({ url }) => {
  return {
    error: url.searchParams.get('error'),
  };
};
