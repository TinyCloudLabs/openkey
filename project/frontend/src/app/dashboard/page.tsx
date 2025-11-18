'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/app/providers';
import { api } from '@/lib/api';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { 
  Shield, 
  Key, 
  Smartphone, 
  LogOut, 
  Plus, 
  Copy, 
  ExternalLink,
  Settings,
  Activity
} from 'lucide-react';
import { truncateAddress, formatDateTime } from '@/lib/utils';

interface UserStats {
  devicesRegistered: number;
  ethereumKeys: number;
  activeRecoveryTokens: number;
  accountAge: number;
}

interface EthereumKey {
  id: string;
  address: string;
  isActive: boolean;
  createdAt: string;
}

export default function DashboardPage() {
  const { user, logout, isLoading } = useAuth();
  const router = useRouter();
  const [stats, setStats] = useState<UserStats | null>(null);
  const [keys, setKeys] = useState<EthereumKey[]>([]);
  const [isGeneratingKey, setIsGeneratingKey] = useState(false);
  const [signMessage, setSignMessage] = useState('');
  const [signResult, setSignResult] = useState('');
  const [isSigningMessage, setIsSigningMessage] = useState(false);

  useEffect(() => {
    if (!isLoading && !user) {
      router.push('/auth/login');
      return;
    }

    if (user) {
      loadDashboardData();
    }
  }, [user, isLoading, router]);

  const loadDashboardData = async () => {
    try {
      const [statsResponse, keysResponse] = await Promise.all([
        api.getUserStats(),
        api.getUserKeys()
      ]);
      
      setStats(statsResponse.stats);
      setKeys(keysResponse.keys);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    }
  };

  const handleGenerateKey = async () => {
    setIsGeneratingKey(true);
    try {
      await api.generateKey();
      await loadDashboardData(); // Refresh data
    } catch (error) {
      console.error('Failed to generate key:', error);
    } finally {
      setIsGeneratingKey(false);
    }
  };

  const handleSignMessage = async () => {
    if (!signMessage.trim()) return;
    
    setIsSigningMessage(true);
    try {
      const result = await api.signMessage(signMessage);
      setSignResult(result.signature);
    } catch (error) {
      console.error('Failed to sign message:', error);
    } finally {
      setIsSigningMessage(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const handleLogout = () => {
    logout();
    router.push('/');
  };

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary"></div>
      </div>
    );
  }

  if (!user) {
    return null;
  }

  const activeKey = keys.find(key => key.isActive);

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-indigo-600" />
              <span className="ml-2 text-2xl font-bold text-gray-900">OpenKey</span>
            </div>
            <div className="flex items-center space-x-4">
              <span className="text-sm text-gray-600">
                Welcome, {user.email}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => router.push('/settings')}
              >
                <Settings className="h-4 w-4 mr-2" />
                Settings
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={handleLogout}
              >
                <LogOut className="h-4 w-4 mr-2" />
                Sign Out
              </Button>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">
                Devices Registered
              </CardTitle>
              <Smartphone className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats?.devicesRegistered || 0}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">
                Ethereum Keys
              </CardTitle>
              <Key className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats?.ethereumKeys || 0}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">
                Account Age
              </CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats?.accountAge || 0} days</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">
                Recovery Tokens
              </CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{stats?.activeRecoveryTokens || 0}</div>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Ethereum Keys */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span>Ethereum Keys</span>
                <Button
                  onClick={handleGenerateKey}
                  disabled={isGeneratingKey}
                  size="sm"
                >
                  {isGeneratingKey ? (
                    <div className="flex items-center">
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Generating...
                    </div>
                  ) : (
                    <>
                      <Plus className="h-4 w-4 mr-2" />
                      Generate Key
                    </>
                  )}
                </Button>
              </CardTitle>
              <CardDescription>
                Manage your Ethereum private keys for signing transactions
              </CardDescription>
            </CardHeader>
            <CardContent>
              {keys.length === 0 ? (
                <div className="text-center py-8">
                  <Key className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-gray-500">No Ethereum keys yet</p>
                  <p className="text-sm text-gray-400">Generate your first key to get started</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {keys.map((key) => (
                    <div
                      key={key.id}
                      className={`p-4 rounded-lg border ${
                        key.isActive 
                          ? 'border-green-200 bg-green-50' 
                          : 'border-gray-200 bg-gray-50'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="flex items-center">
                            <code className="text-sm font-mono">
                              {truncateAddress(key.address)}
                            </code>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyToClipboard(key.address)}
                            >
                              <Copy className="h-4 w-4" />
                            </Button>
                          </div>
                          <p className="text-xs text-gray-500 mt-1">
                            Created {formatDateTime(key.createdAt)}
                          </p>
                        </div>
                        <div className="flex items-center space-x-2">
                          {key.isActive && (
                            <span className="px-2 py-1 text-xs font-medium text-green-800 bg-green-100 rounded-full">
                              Active
                            </span>
                          )}
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => window.open(`https://etherscan.io/address/${key.address}`, '_blank')}
                          >
                            <ExternalLink className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Message Signing */}
          <Card>
            <CardHeader>
              <CardTitle>Sign Message</CardTitle>
              <CardDescription>
                Sign a message with your active Ethereum key
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {!activeKey ? (
                <div className="text-center py-8">
                  <Key className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                  <p className="text-gray-500">No active Ethereum key</p>
                  <p className="text-sm text-gray-400">Generate a key first to sign messages</p>
                </div>
              ) : (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">
                      Message to Sign
                    </label>
                    <textarea
                      value={signMessage}
                      onChange={(e) => setSignMessage(e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                      rows={3}
                      placeholder="Enter your message here..."
                    />
                  </div>

                  <Button
                    onClick={handleSignMessage}
                    disabled={!signMessage.trim() || isSigningMessage}
                    className="w-full"
                  >
                    {isSigningMessage ? (
                      <div className="flex items-center">
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                        Signing...
                      </div>
                    ) : (
                      'Sign Message'
                    )}
                  </Button>

                  {signResult && (
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-2">
                        Signature
                      </label>
                      <div className="flex">
                        <code className="flex-1 p-2 bg-gray-100 rounded-l-md text-xs font-mono break-all">
                          {signResult}
                        </code>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => copyToClipboard(signResult)}
                          className="rounded-l-none"
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  )}

                  <div className="text-xs text-gray-500">
                    Active key: {truncateAddress(activeKey.address)}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Quick Actions */}
        <div className="mt-8">
          <Card>
            <CardHeader>
              <CardTitle>Quick Actions</CardTitle>
              <CardDescription>
                Common tasks and helpful links
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Button
                  variant="outline"
                  onClick={() => router.push('/settings')}
                  className="h-auto p-4 flex flex-col items-center"
                >
                  <Settings className="h-8 w-8 mb-2 text-gray-600" />
                  <span>Account Settings</span>
                </Button>

                <Button
                  variant="outline"
                  onClick={() => router.push('/recovery')}
                  className="h-auto p-4 flex flex-col items-center"
                >
                  <Shield className="h-8 w-8 mb-2 text-gray-600" />
                  <span>Recovery Options</span>
                </Button>

                <Button
                  variant="outline"
                  onClick={() => router.push('/demo')}
                  className="h-auto p-4 flex flex-col items-center"
                >
                  <ExternalLink className="h-8 w-8 mb-2 text-gray-600" />
                  <span>Try Demo</span>
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}