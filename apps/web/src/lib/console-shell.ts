import type { Writable } from 'svelte/store';
import type { ConsoleOverview, OrganizationSummary } from '$lib/api';

export const CONSOLE_SHELL = Symbol('console-shell');

export interface ConsoleShellContext {
  organizations: Writable<OrganizationSummary[]>;
  overview: Writable<ConsoleOverview | null>;
  loading: Writable<boolean>;
  error: Writable<string>;
  mobileOpen: Writable<boolean>;
  refresh: () => Promise<void>;
}
