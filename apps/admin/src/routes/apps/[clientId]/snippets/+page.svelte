<script lang="ts">
	let { data } = $props();

	let activeTab = $state<'sdk' | 'oauth' | 'curl'>('sdk');
	let copiedBlock = $state<string | null>(null);

	const appName = $derived(data.app.name);
	const clientId = $derived(data.app.clientId);
	const redirectUri = $derived(data.app.redirectUris[0] || 'https://your-app.com/callback');

	async function copyCode(code: string, blockId: string) {
		await navigator.clipboard.writeText(code);
		copiedBlock = blockId;
		setTimeout(() => (copiedBlock = null), 2000);
	}

	const sdkInstall = `npm install @openkey/sdk`;

	const sdkUsage = $derived(`import { OpenKey } from '@openkey/sdk';

const openkey = new OpenKey({ appName: '${appName}' });

// Connect user wallet
const { address } = await openkey.connect();
console.log('Connected:', address);`);

	const oauthAuthorize = $derived(`GET https://api.openkey.so/api/auth/oauth2/authorize?
  client_id=${clientId}&
  redirect_uri=${encodeURIComponent(redirectUri)}&
  response_type=code&
  scope=openid&
  code_challenge={challenge}&
  code_challenge_method=S256&
  state={state}`);

	const oauthTokenExchange = $derived(`POST https://api.openkey.so/api/auth/oauth2/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code={authorization_code}&
redirect_uri=${encodeURIComponent(redirectUri)}&
client_id=${clientId}&
code_verifier={verifier}`);

	const pkceHelper = `// Generate PKCE challenge
async function generatePKCE() {
  const verifier = crypto.randomUUID() + crypto.randomUUID();
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await crypto.subtle.digest('SHA-256', data);
  const challenge = btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\\+/g, '-')
    .replace(/\\//g, '_')
    .replace(/=+$/, '');
  return { verifier, challenge };
}`;

	const curlAuthorize = $derived(`# Step 1: Direct user to authorization URL
# (Open in browser)
open "https://api.openkey.so/api/auth/oauth2/authorize?\\
client_id=${clientId}&\\
redirect_uri=${encodeURIComponent(redirectUri)}&\\
response_type=code&\\
scope=openid&\\
code_challenge=\${CHALLENGE}&\\
code_challenge_method=S256&\\
state=\${STATE}"`);

	const curlToken = $derived(`# Step 2: Exchange authorization code for tokens
curl -X POST https://api.openkey.so/api/auth/oauth2/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=authorization_code" \\
  -d "code=\${AUTH_CODE}" \\
  -d "redirect_uri=${redirectUri}" \\
  -d "client_id=${clientId}" \\
  -d "code_verifier=\${VERIFIER}"`);

	const curlUserinfo = `# Step 3: Fetch user info
curl -X GET https://api.openkey.so/api/auth/oauth2/userinfo \\
  -H "Authorization: Bearer \${ACCESS_TOKEN}"`;
</script>

<div class="max-w-3xl">
	<!-- Breadcrumb -->
	<div class="mb-6 flex items-center gap-2 text-sm text-surface-500">
		<a href="/apps" class="hover:text-surface-700 no-underline">Apps</a>
		<span>/</span>
		<a href="/apps/{data.app.clientId}" class="hover:text-surface-700 no-underline">{data.app.name}</a>
		<span>/</span>
		<span class="text-surface-700">Snippets</span>
	</div>

	<div class="mb-8">
		<h1 class="text-2xl font-bold text-surface-900">Integration Snippets</h1>
		<p class="text-surface-600 mt-1">Copy-paste code to integrate <strong>{data.app.name}</strong> with OpenKey.</p>
	</div>

	<!-- Tab Navigation -->
	<div class="flex border-b border-surface-200 mb-6">
		{#each [
			{ id: 'sdk', label: 'JavaScript / TypeScript' },
			{ id: 'oauth', label: 'OAuth 2.1 (PKCE)' },
			{ id: 'curl', label: 'cURL' },
		] as tab}
			<button
				onclick={() => (activeTab = tab.id as 'sdk' | 'oauth' | 'curl')}
				class="px-4 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px
					{activeTab === tab.id
					? 'border-primary-600 text-primary-700'
					: 'border-transparent text-surface-500 hover:text-surface-700'}"
			>
				{tab.label}
			</button>
		{/each}
	</div>

	<!-- SDK Tab -->
	{#if activeTab === 'sdk'}
		<div class="space-y-6">
			<section>
				<h3 class="text-sm font-semibold text-surface-700 mb-2">1. Install the SDK</h3>
				<div class="relative">
					<pre class="bg-surface-900 text-surface-100 rounded-lg p-4 text-sm font-mono overflow-x-auto"><code>{sdkInstall}</code></pre>
					<button
						onclick={() => copyCode(sdkInstall, 'sdk-install')}
						class="absolute top-2 right-2 px-2 py-1 text-xs bg-surface-700 text-surface-300 rounded hover:bg-surface-600 transition-colors"
					>
						{copiedBlock === 'sdk-install' ? 'Copied!' : 'Copy'}
					</button>
				</div>
			</section>

			<section>
				<h3 class="text-sm font-semibold text-surface-700 mb-2">2. Connect a wallet</h3>
				<div class="relative">
					<pre class="bg-surface-900 text-surface-100 rounded-lg p-4 text-sm font-mono overflow-x-auto"><code>{sdkUsage}</code></pre>
					<button
						onclick={() => copyCode(sdkUsage, 'sdk-usage')}
						class="absolute top-2 right-2 px-2 py-1 text-xs bg-surface-700 text-surface-300 rounded hover:bg-surface-600 transition-colors"
					>
						{copiedBlock === 'sdk-usage' ? 'Copied!' : 'Copy'}
					</button>
				</div>
			</section>
		</div>
	{/if}

	<!-- OAuth Tab -->
	{#if activeTab === 'oauth'}
		<div class="space-y-6">
			<section>
				<h3 class="text-sm font-semibold text-surface-700 mb-2">1. Generate PKCE challenge</h3>
				<div class="relative">
					<pre class="bg-surface-900 text-surface-100 rounded-lg p-4 text-sm font-mono overflow-x-auto"><code>{pkceHelper}</code></pre>
					<button
						onclick={() => copyCode(pkceHelper, 'pkce-helper')}
						class="absolute top-2 right-2 px-2 py-1 text-xs bg-surface-700 text-surface-300 rounded hover:bg-surface-600 transition-colors"
					>
						{copiedBlock === 'pkce-helper' ? 'Copied!' : 'Copy'}
					</button>
				</div>
			</section>

			<section>
				<h3 class="text-sm font-semibold text-surface-700 mb-2">2. Redirect to authorization endpoint</h3>
				<div class="relative">
					<pre class="bg-surface-900 text-surface-100 rounded-lg p-4 text-sm font-mono overflow-x-auto whitespace-pre-wrap"><code>{oauthAuthorize}</code></pre>
					<button
						onclick={() => copyCode(oauthAuthorize, 'oauth-authorize')}
						class="absolute top-2 right-2 px-2 py-1 text-xs bg-surface-700 text-surface-300 rounded hover:bg-surface-600 transition-colors"
					>
						{copiedBlock === 'oauth-authorize' ? 'Copied!' : 'Copy'}
					</button>
				</div>
			</section>

			<section>
				<h3 class="text-sm font-semibold text-surface-700 mb-2">3. Exchange code for tokens</h3>
				<div class="relative">
					<pre class="bg-surface-900 text-surface-100 rounded-lg p-4 text-sm font-mono overflow-x-auto whitespace-pre-wrap"><code>{oauthTokenExchange}</code></pre>
					<button
						onclick={() => copyCode(oauthTokenExchange, 'oauth-token')}
						class="absolute top-2 right-2 px-2 py-1 text-xs bg-surface-700 text-surface-300 rounded hover:bg-surface-600 transition-colors"
					>
						{copiedBlock === 'oauth-token' ? 'Copied!' : 'Copy'}
					</button>
				</div>
			</section>
		</div>
	{/if}

	<!-- cURL Tab -->
	{#if activeTab === 'curl'}
		<div class="space-y-6">
			<section>
				<h3 class="text-sm font-semibold text-surface-700 mb-2">1. Open authorization URL</h3>
				<div class="relative">
					<pre class="bg-surface-900 text-surface-100 rounded-lg p-4 text-sm font-mono overflow-x-auto whitespace-pre-wrap"><code>{curlAuthorize}</code></pre>
					<button
						onclick={() => copyCode(curlAuthorize, 'curl-authorize')}
						class="absolute top-2 right-2 px-2 py-1 text-xs bg-surface-700 text-surface-300 rounded hover:bg-surface-600 transition-colors"
					>
						{copiedBlock === 'curl-authorize' ? 'Copied!' : 'Copy'}
					</button>
				</div>
			</section>

			<section>
				<h3 class="text-sm font-semibold text-surface-700 mb-2">2. Exchange authorization code</h3>
				<div class="relative">
					<pre class="bg-surface-900 text-surface-100 rounded-lg p-4 text-sm font-mono overflow-x-auto whitespace-pre-wrap"><code>{curlToken}</code></pre>
					<button
						onclick={() => copyCode(curlToken, 'curl-token')}
						class="absolute top-2 right-2 px-2 py-1 text-xs bg-surface-700 text-surface-300 rounded hover:bg-surface-600 transition-colors"
					>
						{copiedBlock === 'curl-token' ? 'Copied!' : 'Copy'}
					</button>
				</div>
			</section>

			<section>
				<h3 class="text-sm font-semibold text-surface-700 mb-2">3. Fetch user info</h3>
				<div class="relative">
					<pre class="bg-surface-900 text-surface-100 rounded-lg p-4 text-sm font-mono overflow-x-auto whitespace-pre-wrap"><code>{curlUserinfo}</code></pre>
					<button
						onclick={() => copyCode(curlUserinfo, 'curl-userinfo')}
						class="absolute top-2 right-2 px-2 py-1 text-xs bg-surface-700 text-surface-300 rounded hover:bg-surface-600 transition-colors"
					>
						{copiedBlock === 'curl-userinfo' ? 'Copied!' : 'Copy'}
					</button>
				</div>
			</section>
		</div>
	{/if}

	<!-- Footer link back -->
	<div class="mt-8 pt-6 border-t border-surface-200">
		<a
			href="/apps/{data.app.clientId}"
			class="text-sm text-primary-600 hover:text-primary-700 no-underline font-medium"
		>
			&larr; Back to {data.app.name} settings
		</a>
	</div>
</div>
