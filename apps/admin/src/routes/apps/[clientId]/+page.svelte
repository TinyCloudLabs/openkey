<script lang="ts">
	import { goto, invalidateAll } from '$app/navigation';

	let { data } = $props();

	// Editable fields
	let name = $state(data.app.name);
	let uri = $state(data.app.uri || '');
	let icon = $state(data.app.icon || '');
	let redirectUris = $state<string[]>([...data.app.redirectUris]);

	let saving = $state(false);
	let saveError = $state('');
	let saveSuccess = $state(false);

	// Delete confirmation
	let showDeleteConfirm = $state(false);
	let deleting = $state(false);

	// Rotate secret
	let showRotateConfirm = $state(false);
	let rotating = $state(false);
	let newSecret = $state<string | null>(null);
	let copiedSecret = $state(false);
	let copiedId = $state(false);

	function addRedirectUri() {
		redirectUris = [...redirectUris, ''];
	}

	function removeRedirectUri(index: number) {
		if (redirectUris.length <= 1) return;
		redirectUris = redirectUris.filter((_, i) => i !== index);
	}

	function updateRedirectUri(index: number, value: string) {
		redirectUris = redirectUris.map((u, i) => (i === index ? value : u));
	}

	async function copyToClipboard(text: string, field: 'id' | 'secret') {
		await navigator.clipboard.writeText(text);
		if (field === 'id') {
			copiedId = true;
			setTimeout(() => (copiedId = false), 2000);
		} else {
			copiedSecret = true;
			setTimeout(() => (copiedSecret = false), 2000);
		}
	}

	function formatDate(date: string | Date): string {
		return new Date(date).toLocaleDateString('en-US', {
			month: 'short',
			day: 'numeric',
			year: 'numeric',
			hour: '2-digit',
			minute: '2-digit',
		});
	}

	function typeBadgeClasses(type: string | null): string {
		switch (type) {
			case 'web':
				return 'bg-primary-100 text-primary-700';
			case 'spa':
				return 'bg-blue-100 text-blue-700';
			case 'native':
				return 'bg-amber-100 text-amber-700';
			default:
				return 'bg-surface-100 text-surface-600';
		}
	}

	async function handleSave() {
		saveError = '';
		saveSuccess = false;
		saving = true;

		const filteredUris = redirectUris.filter((u) => u.trim().length > 0);
		if (filteredUris.length === 0) {
			saveError = 'At least one redirect URI is required';
			saving = false;
			return;
		}

		try {
			const res = await fetch(`/api/apps/${data.app.clientId}`, {
				method: 'PATCH',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					name,
					uri: uri || undefined,
					icon: icon || undefined,
					redirectUris: filteredUris,
				}),
			});

			if (!res.ok) {
				const result = await res.json();
				saveError = result.error || 'Failed to save changes';
				saving = false;
				return;
			}

			saveSuccess = true;
			await invalidateAll();
			setTimeout(() => (saveSuccess = false), 3000);
		} catch {
			saveError = 'Network error. Please try again.';
		} finally {
			saving = false;
		}
	}

	async function handleDelete() {
		deleting = true;
		try {
			const res = await fetch(`/api/apps/${data.app.clientId}`, { method: 'DELETE' });
			if (!res.ok) {
				const result = await res.json();
				saveError = result.error || 'Failed to delete app';
				deleting = false;
				showDeleteConfirm = false;
				return;
			}
			goto('/apps');
		} catch {
			saveError = 'Network error. Please try again.';
			deleting = false;
			showDeleteConfirm = false;
		}
	}

	async function handleRotateSecret() {
		rotating = true;
		try {
			const res = await fetch(`/api/apps/${data.app.clientId}/rotate-secret`, { method: 'POST' });
			if (!res.ok) {
				const result = await res.json();
				saveError = result.error || 'Failed to rotate secret';
				rotating = false;
				showRotateConfirm = false;
				return;
			}
			const result = await res.json();
			newSecret = result.clientSecret;
			showRotateConfirm = false;
		} catch {
			saveError = 'Network error. Please try again.';
			showRotateConfirm = false;
		} finally {
			rotating = false;
		}
	}
</script>

<div class="max-w-3xl">
	<!-- Breadcrumb -->
	<div class="mb-6">
		<a href="/apps" class="text-sm text-surface-500 hover:text-surface-700 no-underline">&larr; Back to Apps</a>
	</div>

	<!-- Header -->
	<div class="flex items-start justify-between mb-8">
		<div class="flex items-center gap-4">
			{#if data.app.icon}
				<img src={data.app.icon} alt="{data.app.name} icon" class="w-14 h-14 rounded-xl object-cover" />
			{:else}
				<div class="w-14 h-14 bg-primary-100 rounded-xl flex items-center justify-center">
					<span class="text-primary-600 font-bold text-xl">{data.app.name.charAt(0).toUpperCase()}</span>
				</div>
			{/if}
			<div>
				<h1 class="text-2xl font-bold text-surface-900">{data.app.name}</h1>
				<div class="flex items-center gap-2 mt-1">
					<span class="px-2 py-0.5 text-xs font-medium rounded-full {typeBadgeClasses(data.app.type)}">
						{data.app.type || 'web'}
					</span>
					{#if data.app.disabled}
						<span class="px-2 py-0.5 text-xs font-medium rounded-full bg-red-100 text-red-700">Disabled</span>
					{/if}
				</div>
			</div>
		</div>
		<a
			href="/apps/{data.app.clientId}/snippets"
			class="inline-flex items-center gap-2 px-3 py-1.5 text-sm border border-surface-200 rounded-lg hover:bg-surface-50 transition-colors no-underline text-surface-700"
		>
			<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
			</svg>
			Code Snippets
		</a>
	</div>

	{#if saveError}
		<div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-6 text-sm">
			{saveError}
		</div>
	{/if}

	{#if saveSuccess}
		<div class="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded-lg mb-6 text-sm">
			Changes saved successfully.
		</div>
	{/if}

	<!-- Credentials Section -->
	<section class="bg-white border border-surface-200 rounded-lg p-6 mb-6">
		<h2 class="text-lg font-semibold text-surface-900 mb-4">Credentials</h2>

		<!-- Client ID -->
		<div class="mb-4">
			<label class="block text-sm font-medium text-surface-600 mb-1">Client ID</label>
			<div class="flex items-center gap-2">
				<code class="flex-1 px-3 py-2 bg-surface-50 border border-surface-200 rounded-lg text-sm font-mono text-surface-800">
					{data.app.clientId}
				</code>
				<button
					onclick={() => copyToClipboard(data.app.clientId, 'id')}
					class="px-3 py-2 text-sm border border-surface-200 rounded-lg hover:bg-surface-50 transition-colors"
				>
					{copiedId ? 'Copied!' : 'Copy'}
				</button>
			</div>
		</div>

		<!-- Client Secret actions (only for non-public clients) -->
		{#if !data.app.public}
			<div>
				<label class="block text-sm font-medium text-surface-600 mb-1">Client Secret</label>
				<p class="text-xs text-surface-500 mb-2">The client secret is hashed and cannot be displayed. You can rotate it to generate a new one.</p>
				<button
					onclick={() => (showRotateConfirm = true)}
					class="px-3 py-1.5 text-sm border border-amber-300 text-amber-700 rounded-lg hover:bg-amber-50 transition-colors"
				>
					Rotate Secret
				</button>
			</div>
		{/if}
	</section>

	<!-- New Secret Display -->
	{#if newSecret}
		<div class="bg-amber-50 border border-amber-200 rounded-lg p-6 mb-6">
			<h3 class="text-sm font-semibold text-amber-800 mb-2">New Client Secret</h3>
			<div class="flex items-center gap-2 mb-2">
				<code class="flex-1 px-3 py-2 bg-white border border-amber-200 rounded-lg text-sm font-mono text-surface-800 break-all">
					{newSecret}
				</code>
				<button
					onclick={() => copyToClipboard(newSecret!, 'secret')}
					class="px-3 py-2 text-sm border border-amber-300 rounded-lg hover:bg-amber-100 transition-colors whitespace-nowrap"
				>
					{copiedSecret ? 'Copied!' : 'Copy'}
				</button>
			</div>
			<div class="flex items-start gap-2">
				<svg class="w-4 h-4 text-amber-600 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
				</svg>
				<p class="text-sm text-amber-800">Save your new client secret now. You won't be able to see it again.</p>
			</div>
		</div>
	{/if}

	<!-- Settings Form -->
	<section class="bg-white border border-surface-200 rounded-lg p-6 mb-6">
		<h2 class="text-lg font-semibold text-surface-900 mb-4">Settings</h2>

		<form onsubmit={(e) => { e.preventDefault(); handleSave(); }} class="space-y-5">
			<!-- App Name -->
			<div>
				<label for="name" class="block text-sm font-medium text-surface-700 mb-1">App Name</label>
				<input
					id="name"
					type="text"
					bind:value={name}
					required
					class="w-full px-3 py-2 border border-surface-300 rounded-lg text-surface-900 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
				/>
			</div>

			<!-- App Type (read-only) -->
			<div>
				<label class="block text-sm font-medium text-surface-700 mb-1">Application Type</label>
				<p class="px-3 py-2 bg-surface-50 border border-surface-200 rounded-lg text-sm text-surface-600">
					{data.app.type || 'web'} <span class="text-surface-400">(cannot be changed)</span>
				</p>
			</div>

			<!-- Website URL -->
			<div>
				<label for="uri" class="block text-sm font-medium text-surface-700 mb-1">Website URL</label>
				<input
					id="uri"
					type="url"
					bind:value={uri}
					placeholder="https://example.com"
					class="w-full px-3 py-2 border border-surface-300 rounded-lg text-surface-900 placeholder:text-surface-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
				/>
			</div>

			<!-- Icon URL -->
			<div>
				<label for="icon" class="block text-sm font-medium text-surface-700 mb-1">Icon URL</label>
				<input
					id="icon"
					type="url"
					bind:value={icon}
					placeholder="https://example.com/icon.png"
					class="w-full px-3 py-2 border border-surface-300 rounded-lg text-surface-900 placeholder:text-surface-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
				/>
			</div>

			<!-- Redirect URIs -->
			<div>
				<label class="block text-sm font-medium text-surface-700 mb-1">Redirect URIs</label>
				<div class="space-y-2">
					{#each redirectUris as redirectUri, i}
						<div class="flex gap-2">
							<input
								type="url"
								value={redirectUri}
								oninput={(e) => updateRedirectUri(i, e.currentTarget.value)}
								placeholder="https://example.com/callback"
								class="flex-1 px-3 py-2 border border-surface-300 rounded-lg text-surface-900 placeholder:text-surface-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
							/>
							{#if redirectUris.length > 1}
								<button
									type="button"
									onclick={() => removeRedirectUri(i)}
									class="px-3 py-2 text-surface-400 hover:text-red-500 transition-colors"
									title="Remove URI"
								>
									<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
									</svg>
								</button>
							{/if}
						</div>
					{/each}
				</div>
				<button
					type="button"
					onclick={addRedirectUri}
					class="mt-2 text-sm text-primary-600 hover:text-primary-700 font-medium"
				>
					+ Add another redirect URI
				</button>
			</div>

			<!-- Save -->
			<div class="pt-4 border-t border-surface-200">
				<button
					type="submit"
					disabled={saving || !name.trim()}
					class="px-6 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium text-sm disabled:opacity-50 disabled:cursor-not-allowed"
				>
					{saving ? 'Saving...' : 'Save Changes'}
				</button>
			</div>
		</form>
	</section>

	<!-- Metadata -->
	<section class="bg-white border border-surface-200 rounded-lg p-6 mb-6">
		<h2 class="text-lg font-semibold text-surface-900 mb-3">Details</h2>
		<dl class="grid grid-cols-2 gap-3 text-sm">
			<dt class="text-surface-500">Created</dt>
			<dd class="text-surface-800">{formatDate(data.app.createdAt)}</dd>
			<dt class="text-surface-500">Last Updated</dt>
			<dd class="text-surface-800">{formatDate(data.app.updatedAt)}</dd>
			<dt class="text-surface-500">Scopes</dt>
			<dd class="text-surface-800">{data.app.scopes.join(', ')}</dd>
		</dl>
	</section>

	<!-- Danger Zone -->
	<section class="border border-red-200 rounded-lg p-6">
		<h2 class="text-lg font-semibold text-red-700 mb-2">Danger Zone</h2>
		<p class="text-sm text-surface-600 mb-4">
			Deleting this application will revoke all access tokens and remove all user consents. This action cannot be undone.
		</p>
		<button
			onclick={() => (showDeleteConfirm = true)}
			class="px-4 py-2 text-sm bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors font-medium"
		>
			Delete Application
		</button>
	</section>
</div>

<!-- Delete Confirmation Modal -->
{#if showDeleteConfirm}
	<div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
		<div class="bg-white rounded-xl shadow-xl max-w-md w-full p-6">
			<h2 class="text-xl font-bold text-surface-900 mb-2">Delete Application?</h2>
			<p class="text-surface-600 text-sm mb-1">
				This will permanently delete <strong>{data.app.name}</strong> and:
			</p>
			<ul class="text-sm text-surface-600 list-disc pl-5 mb-6 space-y-1">
				<li>Revoke all active access tokens</li>
				<li>Revoke all refresh tokens</li>
				<li>Remove all user consent records</li>
			</ul>
			<div class="flex gap-3 justify-end">
				<button
					onclick={() => (showDeleteConfirm = false)}
					class="px-4 py-2 text-sm border border-surface-200 rounded-lg hover:bg-surface-50 transition-colors"
				>
					Cancel
				</button>
				<button
					onclick={handleDelete}
					disabled={deleting}
					class="px-4 py-2 text-sm bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors font-medium disabled:opacity-50"
				>
					{deleting ? 'Deleting...' : 'Delete Application'}
				</button>
			</div>
		</div>
	</div>
{/if}

<!-- Rotate Secret Confirmation Modal -->
{#if showRotateConfirm}
	<div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
		<div class="bg-white rounded-xl shadow-xl max-w-md w-full p-6">
			<h2 class="text-xl font-bold text-surface-900 mb-2">Rotate Client Secret?</h2>
			<p class="text-surface-600 text-sm mb-4">
				This will generate a new client secret. The old secret will stop working immediately. Existing access tokens will remain valid.
			</p>
			<div class="flex gap-3 justify-end">
				<button
					onclick={() => (showRotateConfirm = false)}
					class="px-4 py-2 text-sm border border-surface-200 rounded-lg hover:bg-surface-50 transition-colors"
				>
					Cancel
				</button>
				<button
					onclick={handleRotateSecret}
					disabled={rotating}
					class="px-4 py-2 text-sm bg-amber-600 text-white rounded-lg hover:bg-amber-700 transition-colors font-medium disabled:opacity-50"
				>
					{rotating ? 'Rotating...' : 'Rotate Secret'}
				</button>
			</div>
		</div>
	</div>
{/if}
