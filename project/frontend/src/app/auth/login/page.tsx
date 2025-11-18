'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/app/providers';
import { WebAuthnClient } from '@/lib/webauthn';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, Fingerprint, AlertCircle, Mail } from 'lucide-react';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [useEmail, setUseEmail] = useState(false);
  const { login } = useAuth();
  const router = useRouter();

  const handlePasskeyLogin = async () => {
    setIsLoading(true);
    setError('');

    try {
      const { user, token } = await WebAuthnClient.authenticate();
      login(user, token);
      router.push('/dashboard');
    } catch (error) {
      console.error('Login error:', error);
      setError(WebAuthnClient.formatError(error));
    } finally {
      setIsLoading(false);
    }
  };

  const handleEmailLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!email) {
      setError('Email is required');
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      const { user, token } = await WebAuthnClient.authenticate(email);
      login(user, token);
      router.push('/dashboard');
    } catch (error) {
      console.error('Login error:', error);
      setError(WebAuthnClient.formatError(error));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex justify-center mb-4">
            <Shield className="h-12 w-12 text-indigo-600" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900">Welcome Back</h1>
          <p className="text-gray-600 mt-2">
            Sign in to your OpenKey account
          </p>
        </div>

        <Card>
          <CardHeader className="text-center">
            <CardTitle>Sign In</CardTitle>
            <CardDescription>
              Use your passkey or email to access your account
            </CardDescription>
          </CardHeader>

          <CardContent className="space-y-6">
            {!useEmail ? (
              // Passkey Login (Default)
              <div className="text-center space-y-6">
                <div className="bg-indigo-50 rounded-lg p-6">
                  <Fingerprint className="h-16 w-16 text-indigo-600 mx-auto mb-4" />
                  <h3 className="text-lg font-semibold text-gray-900 mb-2">
                    Sign in with Passkey
                  </h3>
                  <p className="text-gray-600 text-sm">
                    Use your device's biometrics or security key for quick, 
                    secure access to your account.
                  </p>
                </div>

                <Button
                  onClick={handlePasskeyLogin}
                  disabled={isLoading}
                  className="w-full"
                  size="lg"
                >
                  {isLoading ? (
                    <div className="flex items-center">
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Authenticating...
                    </div>
                  ) : (
                    <>
                      <Fingerprint className="h-5 w-5 mr-2" />
                      Sign in with Passkey
                    </>
                  )}
                </Button>

                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <span className="w-full border-t" />
                  </div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-white px-2 text-muted-foreground">Or</span>
                  </div>
                </div>

                <Button
                  variant="outline"
                  onClick={() => setUseEmail(true)}
                  className="w-full"
                >
                  <Mail className="h-4 w-4 mr-2" />
                  Sign in with Email
                </Button>
              </div>
            ) : (
              // Email Login
              <div className="space-y-4">
                <div className="bg-blue-50 rounded-lg p-4">
                  <div className="flex items-center">
                    <Mail className="h-5 w-5 text-blue-600 mr-2" />
                    <p className="text-sm text-blue-800">
                      Enter your email to authenticate with your registered passkey
                    </p>
                  </div>
                </div>

                <form onSubmit={handleEmailLogin} className="space-y-4">
                  <div>
                    <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
                      Email Address
                    </label>
                    <input
                      type="email"
                      id="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500"
                      placeholder="you@example.com"
                      required
                    />
                  </div>
                  
                  <Button 
                    type="submit" 
                    className="w-full"
                    disabled={isLoading}
                  >
                    {isLoading ? (
                      <div className="flex items-center">
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                        Authenticating...
                      </div>
                    ) : (
                      'Continue with Email'
                    )}
                  </Button>
                </form>

                <Button
                  variant="ghost"
                  onClick={() => setUseEmail(false)}
                  className="w-full text-sm"
                >
                  ← Back to Passkey
                </Button>
              </div>
            )}

            {/* Error Display */}
            {error && (
              <div className="bg-red-50 border border-red-200 rounded-md p-4">
                <div className="flex">
                  <AlertCircle className="h-5 w-5 text-red-400" />
                  <div className="ml-3">
                    <p className="text-sm text-red-800">{error}</p>
                  </div>
                </div>
              </div>
            )}

            {/* WebAuthn Support Check */}
            {!WebAuthnClient.isSupported() && (
              <div className="bg-orange-50 border border-orange-200 rounded-md p-4">
                <div className="flex">
                  <AlertCircle className="h-5 w-5 text-orange-400" />
                  <div className="ml-3">
                    <p className="text-sm text-orange-800">
                      WebAuthn is not supported on this device or browser. 
                      Please use a modern browser with HTTPS.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Navigation */}
            <div className="flex justify-between items-center pt-4">
              <Button variant="ghost" onClick={() => router.push('/')}>
                ← Back to Home
              </Button>
              
              <div className="text-center">
                <Button
                  variant="link"
                  onClick={() => router.push('/auth/register')}
                  className="text-sm"
                >
                  Don't have an account? Sign up
                </Button>
                <br />
                <Button
                  variant="link"
                  onClick={() => router.push('/recovery')}
                  className="text-sm text-gray-500"
                >
                  Need to recover your account?
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}