// Disable SSR for widget pages - they need to run fully on client
// This ensures onMount fires and postMessage communication works
export const ssr = false;
