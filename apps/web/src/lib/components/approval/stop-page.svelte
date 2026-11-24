<script lang="ts">
  import { STOP_PARTS, fill, type StopButton, type StopView } from '@openkey/sdk/approval-copy';
  import { copyText } from '$lib/clipboard';
  import { focusHeading } from '$lib/components/approval/focus-heading';
  import Icon from '$lib/components/approval/icon.svelte';
  import Button from '$lib/components/ui/button.svelte';
  import CloseTabButton from '$lib/components/ui/close-tab-button.svelte';

  interface Props {
    stop: StopView;
    wanted?: string;
    compared?: { address: string; name: string }[];
    retry?: () => void | Promise<void>;
    switchAccount?: () => void | Promise<void>;
    linkWallet?: () => void;
    chooseKey?: () => void;
    cancelOnClose?: () => Promise<void>;
  }

  let { stop, wanted = '', compared = [], retry, switchAccount, linkWallet, chooseKey, cancelOnClose }: Props = $props();
  let copied = $state<'support' | 'developer' | null>(null);
  let switching = $state(false);
  let closing = $state(false);
  let heading = $state<HTMLHeadingElement>();
  $effect(() => {
    const node = heading;
    if (!node) return;
    const frame = requestAnimationFrame(() => focusHeading(node));
    return () => cancelAnimationFrame(frame);
  });
  const labels = $derived({
    close: STOP_PARTS.buttons.close,
    'try-again': STOP_PARTS.buttons.tryAgain,
    'copy-details': copied === 'developer' ? STOP_PARTS.buttons.copiedDetails : STOP_PARTS.buttons.copyDetails,
    'switch-account': STOP_PARTS.buttons.switchAccount,
    'link-wallet': fill(STOP_PARTS.buttons.linkWallet, { short: wanted }),
    'choose-another-key': STOP_PARTS.buttons.chooseAnotherKey,
    'start-again': STOP_PARTS.buttons.startAgain,
    'enter-code': STOP_PARTS.buttons.enterCode,
  });

  async function copy(kind: 'support' | 'developer') {
    const value = kind === 'support' ? stop.support : [stop.support, stop.detail].filter(Boolean).join(' · ');
    if (await copyText(value)) copied = kind;
  }

  async function switchUser() {
    switching = true;
    try {
      await switchAccount?.();
    } finally {
      switching = false;
    }
  }

  async function beforeClose() {
    closing = true;
    await cancelOnClose?.();
  }

  const actions = $derived({
    'try-again': retry,
    'copy-details': stop.support ? () => copy('developer') : undefined,
    'switch-account': switchAccount ? switchUser : undefined,
    'link-wallet': linkWallet,
    'choose-another-key': chooseKey,
  });
  const buttons: StopButton[] = $derived.by(() => {
    const available = stop.buttons.filter((button) =>
      button === 'close' || button === 'enter-code' || (button !== 'start-again' && actions[button]),
    );
    return available.length ? available : ['close'];
  });
</script>

<div class="w-full min-w-0" data-testid="stop-page">
  <p class="m-0 mb-2.5 flex items-center gap-1.5 text-[11.5px] font-semibold tracking-[0.09em] uppercase text-[#b42318]">
    <Icon name="alert" class="h-4 w-4" />
    {stop.marker}
  </p>
  <h1 bind:this={heading} class="m-0 mb-2.5 text-[25px] leading-[1.17] font-bold tracking-[-0.012em] text-balance text-surface-950">{stop.title}</h1>
  <p class="m-0 mb-3.5 text-pretty [overflow-wrap:anywhere]">{stop.body}</p>

  {#if wanted || compared.length > 0}
    <div class="my-4 grid items-start gap-2 rounded-[14px] border border-surface-200 bg-surface-50 p-3 text-[13px] {wanted && compared.length ? 'grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]' : ''}" data-testid="wallet-comparison">
      {#if wanted}
        <div>
          <p class="m-0 text-surface-500">{STOP_PARTS.linkAsks}</p>
          <code class="break-all">{wanted}</code>
        </div>
      {/if}
      {#if compared.length > 0}
        {#if wanted}<span aria-hidden="true" class="pt-3 text-[#b42318]">≠</span>{/if}
        <div>
          <p class="m-0 text-surface-500">{stop.id === 'S17' ? STOP_PARTS.accountHas : STOP_PARTS.youChose}</p>
          {#each compared as item, index (index)}
            <div class="break-words"><code class="break-all">{item.address}</code> {item.name}</div>
          {/each}
        </div>
      {/if}
    </div>
  {/if}

  {#if stop.detail}
    <div class="my-4 rounded-[14px] border border-surface-200 bg-surface-50 p-3 text-[13px] [overflow-wrap:anywhere]">
      <p class="m-0 mb-1 font-semibold">{STOP_PARTS.found}</p>
      <p class="m-0 whitespace-pre-wrap">{stop.detail}</p>
    </div>
  {/if}

  <div class="mt-5 grid gap-2.5">
    {#each buttons as button, index (button)}
      {@const variant = index === 0 ? 'default' : 'secondary'}
      {#if button === 'close'}
        <CloseTabButton class="w-full" secondary={index !== 0} beforeClose={cancelOnClose ? beforeClose : undefined} />
      {:else if button === 'enter-code'}
        <Button {variant} href="/device" class="w-full">{labels[button]}</Button>
      {:else if button !== 'start-again'}
        <Button {variant} class="w-full" onclick={actions[button]} disabled={switching || closing}>{labels[button]}</Button>
      {/if}
    {/each}
  </div>

  {#if stop.extra || stop.buttons.includes('start-again')}
    <p class="mt-3.5 mb-0 text-[13px] text-surface-500">{stop.extra ?? labels['start-again']}</p>
  {/if}

  {#if stop.support}
    <button
      type="button"
      class="mt-6 flex w-full cursor-pointer flex-wrap items-baseline justify-between gap-x-2 gap-y-1 border-0 border-t border-surface-200 bg-transparent px-0 pt-3 text-left text-xs text-surface-500"
      onclick={() => copy('support')}
    >
      <span>{STOP_PARTS.supportLabel}</span>
      <code class="min-w-0 font-mono text-[11.5px] break-words text-surface-700" data-support-line>{stop.support}</code>
      <span role="status" class="font-semibold text-surface-950">{copied === 'support' ? STOP_PARTS.copied : STOP_PARTS.copy}</span>
    </button>
  {/if}
</div>
