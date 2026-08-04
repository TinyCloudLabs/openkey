import document from '$lib/pages/managed-accounts-project.html?raw';

export const GET = () => new Response(document, {
  headers: {
    'cache-control': 'public, max-age=0, must-revalidate',
    'content-type': 'text/html; charset=utf-8',
  },
});
