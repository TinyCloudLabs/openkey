<script lang="ts">
  // An eight-character device code drawn as two groups of four tiles. Read-only, it is one labelled image of the
  // code. Editable, it is one real text input laid over the tiles, so typing, pasting and one-time-code autofill all
  // work; the value is upper-cased, cut to eight letters and numbers, and the dash is added.
  import { formatDeviceUserCode, normalizeDeviceUserCode } from '$lib/device-authorization';
  import { DEVICE, fill } from '@openkey/sdk/approval-copy';

  interface Props {
    /** The code, in any case, with or without the dash. */
    code: string;
    /** Draw an input instead of a read-only code. */
    editable?: boolean;
    /** The input's name comes from this element (editable only). */
    labelledby?: string;
    describedby?: string;
    /** The cleaned code, `ABCD-EFGH` or shorter, after each change (editable only). */
    oninput?: (code: string) => void;
  }

  let { code, editable = false, labelledby, describedby, oninput }: Props = $props();

  let focused = $state(false);
  const chars = $derived(normalizeDeviceUserCode(code));
  const groups = [[0, 1, 2, 3], [4, 5, 6, 7]];

  function tileClass(index: number): string {
    // The tile the next character goes in; the last one once the code is complete.
    const current = editable && focused && index === Math.min(chars.length, 7);
    return current ? 'border-surface-950 bg-white shadow-[0_0_0_3px_rgba(15,17,21,0.08)]' : `border-surface-300 ${editable ? 'bg-white' : 'bg-surface-50'}`;
  }

  function changed(event: Event & { currentTarget: HTMLInputElement }) {
    const next = formatDeviceUserCode(event.currentTarget.value);
    // Write it back even when the cleaned code did not change (a space or a dash typed on its own).
    event.currentTarget.value = next;
    oninput?.(next);
  }
</script>

{#snippet tiles()}
  {#each groups as group, half (half)}
    {#if half === 1}<i class="mx-0.5 h-0.5 w-2.5 flex-none bg-surface-300"></i>{/if}
    {#each group as index (index)}
      <span
        class="grid h-[46px] w-[34px] flex-none place-items-center rounded-[9px] border font-mono text-[23px] font-semibold text-surface-950 min-[600px]:h-[52px] min-[600px]:w-10 min-[600px]:text-[26px] {tileClass(index)}"
      >{chars[index] ?? ''}</span>
    {/each}
  {/each}
{/snippet}

{#if editable}
  <div class="relative mx-auto mt-2.5 mb-1.5 w-fit">
    <div class="flex items-center justify-center gap-[5px]" aria-hidden="true">{@render tiles()}</div>
    <input
      class="absolute inset-0 h-full w-full cursor-text rounded-[9px] border-0 bg-transparent p-0 text-[16px] text-transparent caret-transparent opacity-0 outline-none"
      type="text"
      inputmode="text"
      autocomplete="one-time-code"
      autocapitalize="characters"
      spellcheck="false"
      aria-labelledby={labelledby}
      aria-describedby={describedby}
      value={formatDeviceUserCode(chars)}
      oninput={changed}
      onfocus={() => (focused = true)}
      onblur={() => (focused = false)}
    />
  </div>
{:else}
  <div
    role="img"
    class="mt-2.5 mb-1.5 flex items-center justify-center gap-[5px]"
    aria-label={fill(DEVICE.codeLabel, { first: [...chars.slice(0, 4)].join(' '), second: [...chars.slice(4)].join(' ') })}
  >{@render tiles()}</div>
{/if}
