<script lang="ts">
	import { goto } from '$app/navigation';

	let name = $state('');
	let uri = $state('');
	let icon = $state('');
	let type = $state<'web' | 'spa' | 'native'>('web');
	let redirectUris = $state<string[]>(['']);
	let scopeKeys = $state(false);

	let submitting = $state(false);
	let error = $state('');

	// One-time secret modal state
	let showSecretModal = $state(false);
	let createdClientId = $state('');
	let createdClientSecret = $state<string | null>(null);
	let copiedId = $state(false);
	let copiedSecret = $state(false);

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

	async function handleSubmit() {
		error = '';
		submitting = true;

		const filteredUris = redirectUris.filter((u) => u.trim().length > 0);
		if (filteredUris.length === 0) {
			error = 'At least one redirect URI is required';
			submitting = false;
			return;
		}

		const scopes = ['openid'];
		if (scopeKeys) scopes.push('keys');

		try {
			const res = await fetch('/api/apps', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					name,
					redirectUris: filteredUris,
					uri: uri || undefined,
					icon: icon || undefined,
					type,
					scopes,
				}),
			});

			if (!res.ok) {
				const data = await res.json();
				error = data.error || 'Failed to create app';
				submitting = false;
				return;
			}

			const data = await res.json();
			createdClientId = data.clientId;
			createdClientSecret = data.clientSecret;
			showSecretModal = true;
		} catch (err) {
			error = 'Network error. Please try again.';
		} finally {
			submitting = false;
		}
	}

	function handleDone() {
		goto(`/apps/${createdClientId}`);
	}
</script>

<div class="max-w-2xl">
	<div class="mb-8">
		<a href="/apps" class="text-sm text-surface-500 hover:text-surface-700 no-underline">&larr; Back to Apps</a>
		<h1 class="text-3xl font-bold text-surface-900 mt-3">Create New Application</h1>
		<p class="text-surface-600 mt-1">Register a new OAuth application to integrate with OpenKey.</p>
	</div>

	{#if error}
		<div class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-6 text-sm">
			{error}
		</div>
	{/if}

	<form onsubmit={(e) => { e.preventDefault(); handleSubmit(); }} class="space-y-6">
		<!-- App Name -->
		<div>
			<label for="name" class="block text-sm font-medium text-surface-700 mb-1">
				App Name <span class="text-red-500">*</span>
			</label>
			<input
				id="name"
				type="text"
				bind:value={name}
				required
				placeholder="My Application"
				class="w-full px-3 py-2 border border-surface-300 rounded-lg text-surface-900 placeholder:text-surface-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
			/>
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

		<!-- App Type -->
		<fieldset>
			<legend class="block text-sm font-medium text-surface-700 mb-2">Application Type</legend>
			<div class="flex gap-4">
				{#each [
					{ value: 'web', label: 'Web', desc: 'Server-side app with client secret' },
					{ value: 'spa', label: 'SPA', desc: 'Single-page app, public client' },
					{ value: 'native', label: 'Native', desc: 'Mobile/desktop app with secret' },
				] as option}
					<label
						class="flex-1 cursor-pointer border rounded-lg p-3 transition-colors {type === option.value
							? 'border-primary-500 bg-primary-50'
							: 'border-surface-200 hover:border-surface-300'}"
					>
						<input
							type="radio"
							name="type"
							value={option.value}
							bind:group={type}
							class="sr-only"
						/>
						<span class="block text-sm font-medium text-surface-900">{option.label}</span>
						<span class="block text-xs text-surface-500 mt-0.5">{option.desc}</span>
					</label>
				{/each}
			</div>
		</fieldset>

		<!-- Redirect URIs -->
		<div>
			<label class="block text-sm font-medium text-surface-700 mb-1">
				Redirect URIs <span class="text-red-500">*</span>
			</label>
			<p class="text-xs text-surface-500 mb-2">At least one redirect URI is required for OAuth flows.</p>
			<div class="space-y-2">
				{#each redirectUris as redirectUri, i}
					<div class="flex gap-2">
						<input
							type="url"
							value={redirectUri}
							oninput={(e) => updateRedirectUri(i, e.currentTarget.value)}
							placeholder="https://example.com/callback"
							required={i === 0}
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

		<!-- Scopes -->
		<fieldset>
			<legend class="block text-sm font-medium text-surface-700 mb-2">Scopes</legend>
			<div class="space-y-2">
				<label class="flex items-center gap-2 text-sm">
					<input type="checkbox" checked disabled class="rounded border-surface-300 text-primary-600" />
					<span class="text-surface-700">openid</span>
					<span class="text-xs text-surface-400">(required)</span>
				</label>
				<label class="flex items-center gap-2 text-sm cursor-pointer">
					<input
						type="checkbox"
						bind:checked={scopeKeys}
						class="rounded border-surface-300 text-primary-600 focus:ring-primary-500"
					/>
					<span class="text-surface-700">keys</span>
					<span class="text-xs text-surface-400">(access to Ethereum key operations)</span>
				</label>
			</div>
		</fieldset>

		<!-- Submit -->
		<div class="pt-4 border-t border-surface-200">
			<button
				type="submit"
				disabled={submitting || !name.trim()}
				class="w-full px-4 py-2.5 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium disabled:opacity-50 disabled:cursor-not-allowed"
			>
				{submitting ? 'Creating...' : 'Create Application'}
			</button>
		</div>
	</form>
</div>

<!-- One-time Secret Modal -->
{#if showSecretModal}
	<div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
		<div class="bg-white rounded-xl shadow-xl max-w-lg w-full p-6">
			<div class="flex items-center gap-3 mb-4">
				<div class="w-10 h-10 bg-green-100 rounded-full flex items-center justify-center">
					<svg class="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
					</svg>
				</div>
				<h2 class="text-xl font-bold text-surface-900">Application Created</h2>
			</div>

			<div class="space-y-4">
				<!-- Client ID -->
				<div>
					<label class="block text-sm font-medium text-surface-700 mb-1">Client ID</label>
					<div class="flex items-center gap-2">
						<code class="flex-1 px-3 py-2 bg-surface-100 rounded-lg text-sm font-mono text-surface-800 break-all">
							{createdClientId}
						</code>
						<button
							onclick={() => copyToClipboard(createdClientId, 'id')}
							class="px-3 py-2 text-sm border border-surface-200 rounded-lg hover:bg-surface-50 transition-colors whitespace-nowrap"
						>
							{copiedId ? 'Copied!' : 'Copy'}
						</button>
					</div>
				</div>

				<!-- Client Secret (only for web/native) -->
				{#if createdClientSecret}
					<div>
						<label class="block text-sm font-medium text-surface-700 mb-1">Client Secret</label>
						<div class="flex items-center gap-2">
							<code class="flex-1 px-3 py-2 bg-surface-100 rounded-lg text-sm font-mono text-surface-800 break-all">
								{createdClientSecret}
							</code>
							<button
								onclick={() => copyToClipboard(createdClientSecret!, 'secret')}
								class="px-3 py-2 text-sm border border-surface-200 rounded-lg hover:bg-surface-50 transition-colors whitespace-nowrap"
							>
								{copiedSecret ? 'Copied!' : 'Copy'}
							</button>
						</div>
						<div class="mt-2 flex items-start gap-2 bg-amber-50 border border-amber-200 rounded-lg p-3">
							<svg class="w-4 h-4 text-amber-600 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
								<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
							</svg>
							<p class="text-sm text-amber-800">
								Save your client secret now. You won't be able to see it again.
							</p>
						</div>
					</div>
				{/if}
			</div>

			<div class="mt-6">
				<button
					onclick={handleDone}
					class="w-full px-4 py-2.5 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors font-medium"
				>
					Done
				</button>
			</div>
		</div>
	</div>
{/if}
