// Import this first in any test that loads primary-key.ts (directly or via org-keys.ts).
// primary-key.ts creates the TEE client at module load and refuses to start without an
// explicit TEE_MODE. ES imports evaluate in order, so this runs before the service import.
process.env.TEE_MODE ??= 'development';
