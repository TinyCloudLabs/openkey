'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from './providers';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, Key, Smartphone, Github } from 'lucide-react';

export default function HomePage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!isLoading && user) {
      router.push('/dashboard');
    }
  }, [user, isLoading, router]);

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      {/* Header */}
      <header className="bg-white shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-indigo-600" />
              <span className="ml-2 text-2xl font-bold text-gray-900">OpenKey</span>
            </div>
            <div className="flex space-x-4">
              <Button
                variant="outline"
                onClick={() => router.push('/auth/login')}
              >
                Sign In
              </Button>
              <Button
                onClick={() => router.push('/auth/register')}
              >
                Get Started
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main>
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
          <div className="text-center">
            <h1 className="text-4xl tracking-tight font-extrabold text-gray-900 sm:text-5xl md:text-6xl">
              <span className="block">Secure Authentication with</span>
              <span className="block text-indigo-600">Passkeys & Ethereum</span>
            </h1>
            <p className="mt-3 max-w-md mx-auto text-base text-gray-500 sm:text-lg md:mt-5 md:text-xl md:max-w-3xl">
              OpenKey combines WebAuthn passkeys with Ethereum key management for secure, 
              passwordless authentication. Self-hosted, open-source, and simple to deploy.
            </p>
            <div className="mt-5 max-w-md mx-auto sm:flex sm:justify-center md:mt-8">
              <div className="rounded-md shadow">
                <Button
                  size="lg"
                  onClick={() => router.push('/auth/register')}
                  className="w-full"
                >
                  Create Account
                </Button>
              </div>
              <div className="mt-3 rounded-md shadow sm:mt-0 sm:ml-3">
                <Button
                  size="lg"
                  variant="outline"
                  onClick={() => router.push('/demo')}
                  className="w-full"
                >
                  Try Demo
                </Button>
              </div>
            </div>
          </div>

          {/* Features */}
          <div className="mt-20">
            <div className="grid grid-cols-1 gap-8 sm:grid-cols-2 lg:grid-cols-3">
              <Card className="card-hover">
                <CardHeader>
                  <div className="flex items-center">
                    <Smartphone className="h-8 w-8 text-indigo-600" />
                    <CardTitle className="ml-3">Passwordless Login</CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  <CardDescription>
                    Use your device's built-in biometrics or security keys for fast, 
                    secure authentication without passwords.
                  </CardDescription>
                </CardContent>
              </Card>

              <Card className="card-hover">
                <CardHeader>
                  <div className="flex items-center">
                    <Key className="h-8 w-8 text-indigo-600" />
                    <CardTitle className="ml-3">Ethereum Integration</CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  <CardDescription>
                    Securely manage Ethereum private keys with AES-256 encryption. 
                    Sign transactions and messages directly from your account.
                  </CardDescription>
                </CardContent>
              </Card>

              <Card className="card-hover">
                <CardHeader>
                  <div className="flex items-center">
                    <Shield className="h-8 w-8 text-indigo-600" />
                    <CardTitle className="ml-3">Self-Hosted Security</CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  <CardDescription>
                    Deploy on your own infrastructure with full control over your data. 
                    No dependency on external authentication services.
                  </CardDescription>
                </CardContent>
              </Card>
            </div>
          </div>

          {/* Open Source CTA */}
          <div className="mt-20 bg-white rounded-lg shadow-xl overflow-hidden">
            <div className="px-6 py-8 sm:p-10 lg:p-16">
              <div className="max-w-3xl mx-auto text-center">
                <Github className="h-12 w-12 text-gray-600 mx-auto" />
                <h2 className="mt-6 text-3xl font-extrabold text-gray-900">
                  Open Source & Transparent
                </h2>
                <p className="mt-4 text-lg text-gray-500">
                  OpenKey is licensed under GPL-3.0. Review the code, contribute improvements, 
                  or deploy your own instance. Commercial licenses available.
                </p>
                <div className="mt-8 flex justify-center">
                  <Button
                    variant="outline"
                    size="lg"
                    onClick={() => window.open('https://github.com/tinycloud/openkey', '_blank')}
                  >
                    <Github className="h-5 w-5 mr-2" />
                    View on GitHub
                  </Button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-white">
        <div className="max-w-7xl mx-auto py-12 px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center">
            <div className="flex items-center">
              <Shield className="h-6 w-6 text-indigo-600" />
              <span className="ml-2 text-lg font-semibold text-gray-900">OpenKey</span>
            </div>
            <p className="text-sm text-gray-500">
              © 2024 TinyCloud Team. Licensed under GPL-3.0.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}