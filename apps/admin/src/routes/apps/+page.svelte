<script lang="ts">
	let { data } = $props();

	function formatDate(date: string | Date): string {
		return new Date(date).toLocaleDateString('en-US', {
			month: 'short',
			day: 'numeric',
			year: 'numeric',
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
</script>

<div class="max-w-6xl">
	<div class="flex items-center justify-between mb-8">
		<div>
			<h1 class="text-3xl font-bold text-surface-900">OAuth Applications</h1>
			<p class="text-surface-600 mt-1">Manage your registered OAuth applications</p>
		</div>
		<a
			href="/apps/new"
			class="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors no-underline text-sm font-medium"
		>
			<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />
			</svg>
			Create New App
		</a>
	</div>

	{#if data.apps.length === 0}
		<div class="bg-white border border-surface-200 rounded-lg p-12 text-center">
			<svg class="w-12 h-12 text-surface-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
			</svg>
			<h3 class="text-lg font-medium text-surface-700 mb-2">No applications yet</h3>
			<p class="text-surface-500 mb-6">Create your first OAuth application to get started.</p>
			<a
				href="/apps/new"
				class="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 transition-colors no-underline text-sm font-medium"
			>
				Create New App
			</a>
		</div>
	{:else}
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
			{#each data.apps as app}
				<a
					href="/apps/{app.clientId}"
					class="block bg-white border border-surface-200 rounded-lg p-5 hover:border-primary-300 hover:shadow-sm transition-all no-underline"
				>
					<div class="flex items-start justify-between mb-3">
						<div class="flex items-center gap-3">
							{#if app.icon}
								<img src={app.icon} alt="{app.name} icon" class="w-10 h-10 rounded-lg object-cover" />
							{:else}
								<div class="w-10 h-10 bg-primary-100 rounded-lg flex items-center justify-center">
									<span class="text-primary-600 font-semibold text-sm">{app.name.charAt(0).toUpperCase()}</span>
								</div>
							{/if}
							<div>
								<h3 class="font-semibold text-surface-900 text-base">{app.name}</h3>
								{#if app.disabled}
									<span class="text-xs text-red-600">Disabled</span>
								{/if}
							</div>
						</div>
						<span class="px-2 py-0.5 text-xs font-medium rounded-full {typeBadgeClasses(app.type)}">
							{app.type || 'web'}
						</span>
					</div>

					<div class="space-y-1.5">
						<p class="text-xs text-surface-400 font-mono truncate">{app.clientId}</p>
						<p class="text-xs text-surface-500">Created {formatDate(app.createdAt)}</p>
					</div>
				</a>
			{/each}
		</div>
	{/if}
</div>
