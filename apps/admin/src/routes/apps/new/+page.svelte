<script lang="ts">
	import { goto } from '$app/navigation';

	let name = $state('');
	let uri = $state('');
	let icon = $state('');
	let type = $state<'spa' | 'native'>('spa');
	let redirectUris = $state<string[]>(['']);
	let scopeKeys = $state(false);

	let submitting = $state(false);
	let error = $state('');

	let createdClientId = $state('');

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
			goto(`/apps/${createdClientId}`);
		} catch (err) {
			error = 'Network error. Please try again.';
		} finally {
			submitting = false;
		}
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
					{ value: 'spa', label: 'SPA', desc: 'Single-page web application' },
					{ value: 'native', label: 'Native', desc: 'Mobile or desktop application' },
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

