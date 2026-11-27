<script lang="ts">
  // The extra warning screen for permissions an app may ask for only with a per-permission decision (TC-2927): decrypt,
  // key creation, or blocking and unblocking keys on the encryption network, or on keys outside the app's own area. One card per permission, each with
  // "Reject this permission" and "Allow this permission" and neither chosen to start with. A request that can be split
  // continues with whatever the owner allowed; a request that cannot (exact bytes) is approved or cancelled whole.
  // Wording is Monica's, in capability-review's copy catalog; this file has no sentences of its own.
  import { tick } from "svelte";
  import {
    ELEVATED_ALLOW,
    ELEVATED_ALLOWED_STATUS,
    ELEVATED_CHANGE,
    ELEVATED_CONTINUE,
    ELEVATED_CONTINUE_HINT,
    ELEVATED_REJECT,
    ELEVATED_REJECTED_STATUS,
    ELEVATED_SUB,
    ELEVATED_WHOLE_ALLOW,
    ELEVATED_WHOLE_CANCEL,
    elevatedDecidedAnnouncement,
    elevatedRejectNote,
    elevatedTitle,
    elevatedWholeNote,
  } from "@openkey/capability-review";

  export interface ElevatedCard {
    /** Stable id of the card (the grant it covers). */
    id: string;
    heading: string;
    body: string;
    /** The hint under the Reject and Allow buttons where it differs from the shared one; null for the shared hint. */
    rejectNote?: string | null;
  }

  interface Props {
    cards: ElevatedCard[];
    /** The browser-verified origin host, or null where nothing is verified ("This request"). */
    site: string | null;
    /** False where the request can only be approved or cancelled whole. */
    splittable: boolean;
    /** Splittable: the ids of the cards the owner allowed, the rest rejected. */
    onResolve: (allowedCardIds: string[]) => void;
    /** Not splittable: allow and approve the whole request. */
    onAllowWhole: () => void;
    /** Cancel the whole request (not splittable), or go back (splittable, before deciding). */
    onCancel: () => void;
  }

  let { cards, site, splittable, onResolve, onAllowWhole, onCancel }: Props = $props();

  type Decision = "allow" | "reject";
  let decisions = $state<Record<string, Decision | undefined>>({});
  let announcement = $state("");
  let titleEl = $state<HTMLHeadingElement | null>(null);
  let continueEl = $state<HTMLButtonElement | null>(null);
  const headingEls: Record<string, HTMLElement | null> = {};
  const rejectEls: Record<string, HTMLButtonElement | null> = {};

  const undecided = $derived(cards.filter((card) => decisions[card.id] === undefined));
  const title = $derived(elevatedTitle(site));
  const note = $derived(elevatedRejectNote(site));

  // On open, focus the title; never an Allow button.
  $effect(() => {
    void tick().then(() => titleEl?.focus());
  });

  async function decide(card: ElevatedCard, choice: Decision) {
    decisions = { ...decisions, [card.id]: choice };
    const left = cards.filter((other) => decisions[other.id] === undefined).length;
    announcement = elevatedDecidedAnnouncement(card.heading, choice === "allow", left);
    await tick();
    const next = cards.find((other) => decisions[other.id] === undefined);
    if (next) headingEls[next.id]?.focus();
    else continueEl?.focus();
  }

  async function change(card: ElevatedCard) {
    decisions = { ...decisions, [card.id]: undefined };
    await tick();
    rejectEls[card.id]?.focus();
  }

  function proceed() {
    if (undecided.length > 0) return;
    onResolve(cards.filter((card) => decisions[card.id] === "allow").map((card) => card.id));
  }
</script>

<div class="elevated" role="dialog" aria-modal="true" aria-labelledby="elevated-title">
  <header class="header">
    <h1 id="elevated-title" class="title" tabindex="-1" bind:this={titleEl}>{title}</h1>
    {#if splittable}
      <p class="sub">{ELEVATED_SUB}</p>
    {:else}
      <p class="sub">{elevatedWholeNote(site)}</p>
    {/if}
  </header>

  {#each cards as card, index (card.id)}
    {@const choice = decisions[card.id]}
    <section class="card" role="group" aria-labelledby={`elevated-card-${index}`}>
      <h2 class="card-heading" id={`elevated-card-${index}`} tabindex="-1" bind:this={headingEls[card.id]}>
        <span class="heading-text">{card.heading}</span>
        <span class="pill">Sensitive</span>
      </h2>
      <p class="body">{card.body}</p>
      {#if splittable}
        {#if choice === undefined}
          <div class="pair">
            <button type="button" class="reject" bind:this={rejectEls[card.id]} onclick={() => decide(card, "reject")}>
              {ELEVATED_REJECT}
            </button>
            <button type="button" class="allow" onclick={() => decide(card, "allow")}>{ELEVATED_ALLOW}</button>
          </div>
          <p class="note">{card.rejectNote ?? note}</p>
        {:else}
          <p class="status">
            <span>{choice === "reject" ? ELEVATED_REJECTED_STATUS : ELEVATED_ALLOWED_STATUS}</span>
            <button type="button" class="change" onclick={() => change(card)}>{ELEVATED_CHANGE}</button>
          </p>
        {/if}
      {/if}
    </section>
  {/each}

  {#if splittable}
    <div class="finish">
      {#if undecided.length > 0}
        <p id="elevated-continue-hint" class="hint">{ELEVATED_CONTINUE_HINT}</p>
      {/if}
      <button
        type="button"
        class="continue"
        bind:this={continueEl}
        disabled={undecided.length > 0}
        aria-describedby={undecided.length > 0 ? "elevated-continue-hint" : undefined}
        onclick={proceed}
      >
        {ELEVATED_CONTINUE}
      </button>
    </div>
  {:else}
    <div class="finish whole">
      <button type="button" class="reject" onclick={onCancel}>{ELEVATED_WHOLE_CANCEL}</button>
      <button type="button" class="allow" onclick={onAllowWhole}>{ELEVATED_WHOLE_ALLOW}</button>
    </div>
  {/if}

  <p class="visually-hidden" role="status" aria-live="polite">{announcement}</p>
</div>

<style>
  .elevated {
    display: flex;
    flex-direction: column;
    gap: 14px;
    width: min(100%, 560px);
    max-width: 560px;
    margin: 0 auto;
    padding: 18px;
    box-sizing: border-box;
    background: #fff;
    border: 1px solid #dbe2ea;
    border-radius: 16px;
    color: #0f172a;
  }
  .title {
    margin: 0;
    font-size: 18px;
    font-weight: 700;
    line-height: 1.3;
    overflow-wrap: anywhere;
  }
  /* The title and card headings take focus from script (screen readers need it); a mouse or touch user needs no box
     around them. A keyboard user still sees the focus ring on every button. */
  .title:focus,
  .card-heading:focus {
    outline: none;
  }
  .sub {
    margin: 4px 0 0;
    font-size: 13px;
    line-height: 1.45;
    color: #475569;
    overflow-wrap: anywhere;
  }
  .card {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 12px;
    border: 1px solid #f2c0c0;
    border-radius: 12px;
    background: #fffafa;
  }
  .card-heading {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 8px;
    margin: 0;
    font-size: 14px;
    font-weight: 700;
    line-height: 1.35;
  }
  .heading-text {
    overflow-wrap: anywhere;
  }
  .pill {
    flex: 0 0 auto;
    border: 1px solid #f2c0c0;
    border-radius: 999px;
    background: #fff7f7;
    color: #9f2424;
    padding: 2px 7px;
    font-size: 10px;
    font-weight: 700;
    line-height: 1.3;
  }
  .body,
  .note,
  .hint {
    margin: 0;
    font-size: 13px;
    line-height: 1.45;
    color: #334155;
    overflow-wrap: anywhere;
  }
  .note,
  .hint {
    color: #475569;
    font-size: 12px;
  }
  .pair,
  .finish.whole {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  button {
    min-height: 44px;
    width: 100%;
    border-radius: 10px;
    border: 1px solid #cbd5e1;
    background: #fff;
    color: #0f172a;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
  }
  button.reject {
    background: #0f172a;
    border-color: #0f172a;
    color: #fff;
  }
  /* Continue is the primary action, the same ink as OpenKey's Approve and its disabled look. */
  button.continue {
    background: #0f172a;
    border-color: #0f172a;
    color: #fff;
  }
  button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
  button:focus-visible {
    outline: 2px solid #1d4ed8;
    outline-offset: 2px;
  }
  .status {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin: 0;
    font-size: 13px;
    color: #0f172a;
  }
  button.change {
    width: auto;
    min-height: 44px;
    padding: 0 12px;
    border: none;
    background: transparent;
    color: #1d4ed8;
    text-decoration: underline;
  }
  .finish {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    margin: -1px;
    padding: 0;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }
</style>
