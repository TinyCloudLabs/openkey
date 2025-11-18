import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { Providers } from './providers';

const inter = Inter({ subsets: ['latin'] });

export const metadata: Metadata = {
  title: 'OpenKey - Secure Authentication with Passkeys',
  description: 'Open-source authentication service combining WebAuthn with Ethereum key management',
  keywords: 'webauthn, passkeys, ethereum, authentication, security, blockchain',
  authors: [{ name: 'TinyCloud Team' }],
  openGraph: {
    title: 'OpenKey - Secure Authentication with Passkeys',
    description: 'Open-source authentication service combining WebAuthn with Ethereum key management',
    type: 'website',
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <Providers>
          {children}
        </Providers>
      </body>
    </html>
  );
}