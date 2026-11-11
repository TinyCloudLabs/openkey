<script lang="ts">
  import { onMount } from 'svelte';
  import { goto } from '$app/navigation';
  import { authClient } from '$lib/auth-client';
  import { orgAdminAction, orgAdminRequest } from '$lib/org-key-admin-api';
  import { copyText } from '$lib/clipboard';

  let { keyId, invitationId }: { keyId?: string; invitationId?: string } = $props();
  type Grant = { grantee?: { name: string | null; email: string } | null; id: string; role: 'OWNER' | 'ADMIN'; granteeUserId: string | null; granteeDid: string | null; invitedEmail?: string; invitedUserId?: string; acceptedAt: string | null; invitationExpiresAt: string | null };
  type Key = { id: string; address: string; orgKey: { orgId: string; orgName: string; controllerDid: string } };
  type Roster = { role: 'OWNER' | 'ADMIN'; grants: Grant[]; key: Key; handle: string | null; events: { id: string; actorUserId: string; kind: string; createdAt: string }[] };
  type Invitation = { key: Key; handle: string | null; inviter: { name: string | null; email: string } | null; invitedEmail: string | null; personalDid: string | null; accepted: boolean; expiresAt: string };
  const session = authClient.useSession();
  const permissions = 'Admins can never move funds, export the key or add admins.';
  let roster = $state<Roster | null>(null);
  let invitation = $state<Invitation | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let pendingCap = $state(false);
  let notice = $state('');
  let error = $state('');
  let inviting = $state(false);
  let targetKind = $state<'email' | 'accountId'>('email');
  let target = $state('');
  let pendingLink = $state('');
  let invitationState = $state<'expired' | 'cancelled' | null>(null);
  let maskedEmail = $state<string | null>(null);
  let proofNeeded = $state(false);
  let deliveryFailed = $state(false);
  let copied = $state(false);
  let ended = $state(false);
  let accepted = $state(false);
  let confirming = $state<Grant | null>(null);
  const key = $derived(roster?.key ?? invitation?.key);
  const ownerName = $derived(roster?.grants.find(grant => grant.role === 'OWNER')?.grantee?.name || roster?.grants.find(grant => grant.role === 'OWNER')?.granteeUserId || '');
  const confirmName = $derived(confirming?.grantee?.name || confirming?.granteeUserId || confirming?.invitedEmail || confirming?.invitedUserId || '');
  const handle = $derived(roster?.handle ?? invitation?.handle);

  let invitationToken: string | undefined;
  onMount(() => {
    if (invitationId) {
      const secret = new URLSearchParams(location.hash.slice(1)).get('token');
      if (secret) { invitationToken = secret; sessionStorage.setItem(`org-invitation:${invitationId}`, secret); }
      else invitationToken = sessionStorage.getItem(`org-invitation:${invitationId}`) ?? undefined;
      if (location.hash) history.replaceState(history.state, '', location.pathname);
    }
    void load();
  });
  async function load() {
    loading = true; error = ''; pendingCap = false;
    try {
      if (window.top !== window.self) throw new Error('403');
      const current = await authClient.getSession();
      if (!current.data) {
        await goto(`/auth/login?redirect=${encodeURIComponent(location.pathname)}`); return;
      }
      if (invitationId) {
        const result = await orgAdminRequest<Invitation | { maskedEmail: string | null } | { state: 'expired' | 'cancelled' }>(`/org-key-invitations/${encodeURIComponent(invitationId)}`, undefined, invitationToken);
        if ('state' in result) { invitationState = result.state; invitation = null; proofNeeded = false; }
        else if ('maskedEmail' in result) { proofNeeded = true; maskedEmail = result.maskedEmail; }
        else { invitation = result; proofNeeded = false; }
      }
      else {
        roster = await orgAdminRequest<Roster>(`/org-keys/${encodeURIComponent(keyId!)}/admins`);
        if (confirming && !roster.grants.some(grant => grant.id === confirming!.id)) confirming = null;
      }
    } catch (cause) {
      if (roster?.role === 'ADMIN' && cause instanceof Error && cause.message === '403') ended = true;
      else error = 'Couldn’t load admins. Check your connection, then try again.';
    } finally { loading = false; }
  }
  async function sendInvitation() {
    if (busy || !keyId) return;
    busy = true; error = ''; pendingCap = false;
    try {
      const base = `/org-keys/${encodeURIComponent(keyId)}/admin-invitations`;
      const result = await orgAdminAction<{ invitationId: string; delivery?: string }>(`${base}/challenge`, base, { [targetKind]: target });
      deliveryFailed = result.delivery === 'failed';
      pendingLink = `${location.origin}/org-key-invitations/${encodeURIComponent(result.invitationId)}`;
      inviting = false;
      await load();
    } catch (cause) {
      const code = cause instanceof Error && 'code' in cause ? cause.code : null;
      pendingCap = code === 'pending_invitation_limit';
      error = code === 'invitation_rate_limited' ? "You've sent several invitations in the last minute. Wait a minute, then try again."
        : code === 'pending_invitation_limit' ? 'This organisation key already has 50 pending invitations. Cancel one, or wait for one to expire, then invite again.'
        : 'Couldn’t load admins. Check your connection, then try again.';
    }
    finally { busy = false; }
  }
  async function accept() {
    if (busy || !invitationId) return;
    busy = true; error = '';
    try {
      const base = `/org-key-invitations/${encodeURIComponent(invitationId)}`;
      await orgAdminAction(`${base}/accept-challenge`, `${base}/accept`);
      accepted = true;
    } catch { error = 'Couldn’t load admins. Check your connection, then try again.'; }
    finally { busy = false; }
  }
  async function revoke() {
    if (busy || !confirming || !keyId) return;
    busy = true; error = '';
    const leaving = roster?.role === 'ADMIN';
    const wasPending = !confirming.acceptedAt;
    const person = confirmName;
    try {
      const base = `/org-keys/${encodeURIComponent(keyId)}/admins/${encodeURIComponent(confirming.id)}`;
      await orgAdminAction(`${base}/revoke-challenge`, `${base}/revoke`);
      confirming = null;
      if (leaving) ended = true; else { await load(); notice = wasPending ? `Invitation cancelled. ${person} can no longer accept it.` : `${person} is no longer an admin. If they approved any changes, those changes stay in place.`; }
    } catch { error = 'Couldn’t load admins. Check your connection, then try again.'; }
    finally { busy = false; }
  }
  function date(value: string) {
    return new Date(value).toLocaleString('en-GB', { timeZone: 'UTC', dateStyle: 'long', timeStyle: 'short' }) + ' UTC';
  }
  async function emailSignIn() { await authClient.signOut(); await goto(`/auth/login?redirect=${encodeURIComponent(location.pathname)}`); }
  const eventLabels: Record<string, string> = { invited: 'Invitation sent', accepted: 'Invitation accepted', cancel: 'Invitation cancelled', remove: 'Admin removed', leave: 'Admin left', 'delivery-failed': "Invitation email couldn't be sent" };
  async function copyLink(value: string) { await copyText(value); copied = true; }
</script>

<svelte:head><title>Organisation admins · OpenKey</title></svelte:head>
<main>
  <nav aria-label="Breadcrumb"><a href="/dashboard">Keys</a> / {invitationId ? 'Invitation' : 'Admins'}</nav>
  {#if ended}
    <h1>Your admin access has ended</h1>
    <p>You’re no longer an admin for <bdi>{key?.orgKey.orgName}</bdi>. If you approved any changes, those changes stay in place.</p>
    <a href="/dashboard">Back to keys</a>
  {:else}
    <div class="titlebar"><h1>{invitationId ? (invitationState === 'expired' ? 'This invitation has expired' : invitationState === 'cancelled' ? 'This invitation was cancelled' : accepted ? 'You’re now an admin' : invitation?.accepted ? 'You’ve already accepted' : 'Become an organisation admin') : inviting ? 'Invite an admin' : 'Organisation admins'}</h1>
      {#if roster?.role === 'OWNER' && !inviting}<button class="primary" onclick={() => inviting = true}>Invite admin</button>{/if}
    </div>
    {#if key}
      <h2><bdi>{handle ? `${handle}.credentials.org` : key.orgKey.orgId}</bdi></h2>
      <p><span class="label">Organisation name (set by the organisation, unverified)</span><bdi>{key.orgKey.orgName}</bdi></p>
      <div class="key"><div><span class="label">Organisation key</span><code>{key.address}</code></div><details><summary>Organisation ID</summary><code>{key.orgKey.orgId}</code></details></div>
    {/if}
    {#if loading}<p role="status">Loading people with access…</p>{/if}
    {#if notice}<div class="notice" role="status">{notice}</div>{/if}
    {#if error}<div class="notice error" role="alert">{error}</div>{#if !pendingCap}<button onclick={load} disabled={busy}>Try again</button>{/if}{/if}
    {#if invitationState}<p>Ask the organisation owner for a new invitation.</p><a href="/dashboard">Go to OpenKey</a>{/if}
    {#if proofNeeded}<section class="form"><p>{maskedEmail ? `This invitation is for ${maskedEmail}. Sign in with that email to see it.` : 'Sign in with the invited account or verify the invited email to see this invitation.'}</p><button onclick={emailSignIn}>Sign in with email</button></section>{/if}
    {#if pendingLink}
      <div class="notice"><p>{deliveryFailed ? "The invitation is ready, but the email couldn't be sent. Copy the invitation link and send it to them yourself." : `Invitation created for ${target}. If they don't get the email, copy the invitation link and send it to them.`}</p><a href={pendingLink}>Review invitation</a><button onclick={() => copyLink(pendingLink)}>{copied ? 'Invitation link copied' : 'Copy invitation link'}</button><p>Only the invited person can accept it.</p></div>
    {/if}
    {#if invitation && !loading}
      <section class="form">
        <p><span class="label">Your account</span><bdi>{$session.data?.user.name} · {$session.data?.user.id}</bdi></p>
        {#if invitation.personalDid}<details><summary>Personal key</summary><code>{invitation.personalDid}</code></details>{/if}
        <p><span class="label">Invited by</span><bdi>{invitation.inviter?.name} · {invitation.inviter?.email}</bdi></p>
        {#if invitation.invitedEmail}<p><span class="label">Invited email</span><bdi>{invitation.invitedEmail}</bdi></p>{/if}
        <p>{permissions}</p><p><bdi>{invitation.inviter?.name || invitation.inviter?.email}</bdi> remains the owner. You can stop being an admin at any time.</p><p>This invitation expires {date(invitation.expiresAt)}.</p>
        {#if accepted || invitation.accepted}<a href={`/dashboard/org-keys/${encodeURIComponent(invitation.key.id)}/admins`}>Back to organisation key</a>
        {:else if !invitation.personalDid}<p>Finish setting up your OpenKey account before you accept this invitation.</p><a class="setup" href="/dashboard">Set up OpenKey</a>
        {:else}<div class="actions"><button class="primary" onclick={accept} disabled={busy}>Accept with passkey</button><a href="/dashboard">Not now</a></div>{/if}
      </section>
    {:else if inviting}
      <form class="form" onsubmit={(event) => { event.preventDefault(); void sendInvitation(); }}>
        <h2>Who would you like to invite?</h2>
        <div class="actions"><button type="button" disabled={busy} aria-pressed={targetKind === 'email'} onclick={() => targetKind = 'email'}>Email</button><button type="button" disabled={busy} aria-pressed={targetKind === 'accountId'} onclick={() => targetKind = 'accountId'}>OpenKey account</button></div>
        <label for="invite-target">{targetKind === 'email' ? 'Email address' : 'OpenKey account ID'}</label>
        <input id="invite-target" type={targetKind === 'email' ? 'email' : 'text'} bind:value={target} disabled={busy} required />
        {#if targetKind === 'email'}<p>They can accept even if they haven’t used OpenKey before.</p>{/if}
        <h3>What admins can’t do</h3><p>{permissions}</p><p>You remain the owner.</p>
        <div class="actions"><button class="primary" disabled={busy}>Send invitation</button><button type="button" onclick={() => inviting = false} disabled={busy}>Cancel</button></div>
        <p class="muted">Use your passkey to send this invitation.</p>
      </form>
    {:else if roster && !loading}
      <div class="columns"><section><h2>People with access</h2>
        {#each roster.grants as grant (grant.id)}
          <div class="person"><div><strong><bdi>{grant.grantee?.name || grant.granteeUserId || grant.invitedEmail || grant.invitedUserId}</bdi></strong>{#if grant.grantee?.email}<p class="muted"><bdi>{grant.grantee.email}</bdi></p>{/if}{#if grant.granteeDid}<details><summary>Personal key</summary><code>{grant.granteeDid}</code></details>{/if}
            {#if !grant.acceptedAt && grant.invitationExpiresAt}<p class="muted">This invitation expires {date(grant.invitationExpiresAt)}.</p><button onclick={() => copyLink(`${location.origin}/org-key-invitations/${encodeURIComponent(grant.id)}`)}>{copied ? 'Invitation link copied' : 'Copy invitation link'}</button>{/if}
          </div><div><span class="badge">{grant.role === 'OWNER' ? 'Owner' : grant.acceptedAt ? 'Admin' : 'Pending'}</span>
            {#if grant.role === 'ADMIN'}<button disabled={busy} onclick={() => confirming = grant}>{!grant.acceptedAt ? 'Cancel invitation' : roster.role === 'OWNER' ? 'Remove' : 'Stop being an admin'}</button>{/if}
          </div></div>
        {/each}
        {#if roster.grants.length === 1 && roster.role === 'OWNER'}<h3>You’re the only person with access</h3><p>Invite someone to become an admin.</p>{/if}
        {#if confirming}<div class="form"><h2>{!confirming.acceptedAt ? 'Cancel this invitation?' : roster.role === 'OWNER' ? `Remove ${confirmName} as an admin?` : 'Stop being an admin?'}</h2><p><bdi>{confirmName}</bdi></p><p>{!confirming.acceptedAt ? `${confirmName} won’t be able to accept this invitation. You can invite them again later.` : roster.role === 'OWNER' ? `${confirmName} will no longer be an admin. If they approved any changes, those changes will stay in place.` : `Your admin access will end. You can ask ${ownerName} for a new invitation if you need access again.`}</p><p><bdi>{ownerName}</bdi> remains the owner.</p><div class="actions"><button onclick={revoke} disabled={busy}>{!confirming.acceptedAt ? 'Cancel invitation' : roster.role === 'OWNER' ? 'Remove admin' : 'Leave organisation key'}</button><button onclick={() => confirming = null} disabled={busy}>Cancel</button></div></div>{/if}
        {#if roster.role === 'OWNER'}<section class="activity"><h2>Recent activity</h2>{#each roster.events as event (event.id)}<p><bdi>{event.actorUserId}</bdi> · {eventLabels[event.kind] ?? event.kind} <time datetime={event.createdAt}>{date(event.createdAt)}</time></p>{/each}</section>{/if}
      </section><aside><h3>What admins can’t do</h3><p>{permissions}</p>{#if roster.role === 'OWNER'}<p>Only you can invite or remove admins. You remain the owner.</p>{/if}</aside></div>
    {/if}
  {/if}
</main>
<style>
  a.setup{display:inline-block;background:#2a56f6;color:white;padding:10px 15px;border-radius:8px;font-weight:600;text-decoration:none;min-height:44px;box-sizing:border-box}
  main{max-width:1040px;margin:36px auto 70px;padding:0 24px;color:#1a1c21;line-height:1.5}nav{font-size:14px;margin-bottom:24px;color:#475569}a{color:#1e42c8;text-underline-offset:4px}h1{font-size:32px;line-height:1.2;letter-spacing:-.025em;margin:0 0 12px;font-weight:650}h2{font-size:20px;line-height:1.3;margin:0 0 8px}h3{font-size:16px}.titlebar,.actions{display:flex;align-items:center;justify-content:space-between;gap:16px}.actions{justify-content:flex-start;flex-wrap:wrap;margin:20px 0}button,input{font:inherit}button{min-height:44px;border:1px solid #cbd5e1;background:white;color:#334155;border-radius:8px;padding:9px 15px;font-weight:600;cursor:pointer}button:hover{background:#eef3ff}button.primary{background:#2a56f6;color:white;border-color:#2a56f6}button:disabled{opacity:.6;cursor:wait}.key{display:flex;gap:24px;flex-wrap:wrap;padding:20px 0;border-bottom:1px solid #e2e8f0;margin-bottom:28px}.label{display:block;color:#475569;font-size:13px;margin-bottom:4px}code,bdi{overflow-wrap:anywhere}code{font-size:14px}.columns{display:grid;grid-template-columns:minmax(0,1fr) 255px;gap:46px}.person{display:flex;justify-content:space-between;gap:14px;align-items:center;padding:18px 0;border-top:1px solid #e2e8f0}.person>div{min-width:0}.badge{display:inline-block;font-size:12px;font-weight:600;padding:4px 8px;border-radius:4px;background:#eef3ff;color:#17379c}.notice{padding:15px 18px;background:#eef3ff;color:#17379c;border-radius:8px;margin:20px 0}.notice.error{background:#fff1f1;color:#892525}.form{background:white;border:1px solid #e2e8f0;border-radius:12px;padding:28px;max-width:650px;margin:26px 0}.form p{margin:12px 0}.form details{margin:12px 0}.person p{margin:4px 0}.form label{display:block;margin-bottom:8px}input{width:100%;min-height:44px;border:1px solid #94a3b8;border-radius:8px;padding:10px;box-sizing:border-box}.muted,aside{color:#475569;font-size:14px}aside{border-top:1px solid #cbd5e1;padding-top:18px}.activity{margin-top:42px}time{display:block;font-size:13px;color:#475569}:focus-visible{outline:2px solid #2a56f6;outline-offset:3px}@media(max-width:700px){main{padding:0 20px}.columns{grid-template-columns:1fr;gap:24px}.titlebar{align-items:flex-start;flex-wrap:wrap}.person{align-items:flex-start;flex-wrap:wrap}.form{padding:20px}}
</style>
