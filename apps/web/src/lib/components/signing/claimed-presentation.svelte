<script lang="ts">
  // The app's own words about its sign request, in the app's voice and marked as unchecked. The verified origin above
  // stays the only identity on the screen. Every value is plain text, set apart in its own direction (`<bdi>`), and
  // the icon (a small PNG, JPEG or WebP data URI the page already accepted) has no alt text: it names nothing.
  import type { ClaimedPresentationView } from "$lib/claimed-presentation";

  interface Props {
    view: ClaimedPresentationView;
  }

  let { view }: Props = $props();
</script>

<section class="claimed" aria-label="What the app says about itself" data-testid="claimed-presentation">
  {#if view.verified}
    <p class="claim-line" data-claim="verified-on-behalf-of"><span>{view.verified.before}<bdi>{view.verified.value}</bdi>{view.verified.after}</span></p>
  {/if}
  {#each view.claims as claim (claim.kind)}
    <p class="claim-line" data-claim={claim.kind}>
      {#if claim.kind === "name" && view.iconUrl}
        <img class="claim-icon" src={view.iconUrl} alt="" width="20" height="20" />
      {/if}
      <span>{claim.before}<bdi>{claim.value}</bdi>{claim.after}</span>
    </p>
  {/each}
  {#if view.closing}
    <p class="claim-closing" data-claim="closing">{view.closing}</p>
  {/if}
</section>

<style>
  .claimed {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 8px 12px;
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 12px;
  }
  .claim-line {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0;
    font-size: 12px;
    line-height: 1.4;
    color: #475569;
    overflow-wrap: anywhere;
  }
  .claim-icon {
    flex: none;
    width: 20px;
    height: 20px;
    border-radius: 4px;
    object-fit: cover;
  }
  .claim-closing {
    margin: 0;
    font-size: 12px;
    line-height: 1.4;
    color: #64748b;
  }
</style>
