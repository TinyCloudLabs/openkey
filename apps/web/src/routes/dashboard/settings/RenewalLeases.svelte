<script lang="ts">
  import { api } from '$lib/api';
  import { leaseStatements, nodeHost, renewalLeaseCopy as text, type RenewalLease } from '$lib/renewal-leases';

  let { leases, onchanged }: { leases: RenewalLease[]; onchanged: () => void | Promise<void> } = $props();
  let busyCid = $state<string | null>(null);
  let notice = $state('');
  let error = $state('');

  type Eip1193 = { request: (args: { method: string; params?: unknown[] }) => Promise<unknown> };

  /** The owner wallet signs the exact revocation message the API prepared for this lease. */
  async function walletSignature(message: string): Promise<string> {
    const provider = (window as Window & { ethereum?: Eip1193 }).ethereum;
    if (!provider) throw new Error(text.walletUnavailable);
    const owner = /^0x[0-9a-fA-F]{40}$/m.exec(message)?.[0]?.toLowerCase();
    const accounts = await provider.request({ method: 'eth_requestAccounts' }) as string[];
    const account = accounts.find((candidate) => candidate.toLowerCase() === owner);
    if (!account) throw new Error(text.walletUnavailable);
    try {
      return await provider.request({ method: 'personal_sign', params: [message, account] }) as string;
    } catch {
      throw new Error(text.walletDeclined);
    }
  }

  async function stop(lease: RenewalLease) {
    if (busyCid) return;
    busyCid = lease.leaseCid;
    notice = '';
    error = '';
    try {
      let result = await api.stopRenewalLease(lease.leaseCid);
      if ('walletMessage' in result) {
        notice = text.walletPrompt;
        const signature = await walletSignature(result.walletMessage);
        result = await api.stopRenewalLease(lease.leaseCid, { siwe: result.walletMessage, signature });
      }
      notice = text.stopped(lease.grantExpiresAt);
      await onchanged();
    } catch (cause) {
      notice = '';
      // The wallet steps throw the owner's own words; an API refusal reads the same whatever the server said.
      error = cause instanceof Error && !('status' in cause) && cause.message ? cause.message : text.failed;
    } finally {
      busyCid = null;
    }
  }

  function day(value: string): string {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? '' : date.toLocaleDateString(undefined, { dateStyle: 'medium' });
  }
</script>

<div>
  <h2 class="text-xl font-semibold text-surface-900">{text.title}</h2>
  <p class="mt-1 text-sm text-surface-500">{text.intro}</p>

  {#if notice}<p role="status" class="mt-4 rounded-lg border border-surface-200 bg-surface-50 p-3 text-sm text-surface-700">{notice}</p>{/if}
  {#if error}<p role="alert" class="mt-4 text-sm text-red-600">{error}</p>{/if}

  {#if leases.length === 0}
    <p class="py-4 text-sm text-surface-500">{text.empty}</p>
  {/if}
  <ul class="mt-4 flex flex-col gap-3">
    {#each leases as lease (lease.leaseCid)}
      <li class="flex flex-col gap-3 rounded-xl border border-surface-200 bg-surface-50 p-4 sm:flex-row sm:items-center sm:justify-between" data-testid="renewal-lease">
        <div class="min-w-0">
          <p class="break-words font-semibold text-surface-900">{lease.reason || text.untitled(nodeHost(lease.nodeOrigin))}</p>
          {#each leaseStatements(lease.grantSiwe) as line}
            <p class="mt-1 break-words text-sm text-surface-600" data-testid="renewal-lease-permission">{line}</p>
          {/each}
          <p class="mt-1 text-xs text-surface-500">
            {text.renewsUntil} <time datetime={lease.leaseExpiresAt}>{day(lease.leaseExpiresAt)}</time>
            · {text.approved} <time datetime={lease.approvedAt}>{day(lease.approvedAt)}</time>
          </p>
        </div>
        <button type="button" disabled={busyCid !== null} onclick={() => stop(lease)}
          class="shrink-0 rounded-lg border border-surface-300 bg-white px-3 py-1.5 text-sm font-medium text-surface-700 hover:border-surface-400 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-surface-900 disabled:cursor-not-allowed disabled:opacity-60">
          {busyCid === lease.leaseCid ? text.stopping : text.stop}
        </button>
      </li>
    {/each}
  </ul>
</div>
