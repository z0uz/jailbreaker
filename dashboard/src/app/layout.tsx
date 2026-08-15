import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Home as HomeIcon, Search, Crosshair, Blocks, Settings, Bell } from 'lucide-react';
import Link from 'next/link';

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Aegis | AI Security Dashboard",
  description: "Advanced AI Security Scanning Engine",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col bg-[#09090b] text-neutral-200">
        <div className="flex min-h-screen">
          {/* Sidebar */}
          <aside className="w-64 border-r border-neutral-800/50 bg-[#0c0c0e] flex flex-col hidden md:flex">
            <div className="h-16 flex items-center px-6 border-b border-neutral-800/50">
              <div className="flex items-center space-x-3 text-neutral-100 font-semibold tracking-tight">
                <div className="w-6 h-6 rounded bg-neutral-100 text-neutral-900 flex items-center justify-center font-bold text-xs">
                  A
                </div>
                <span>Aegis</span>
              </div>
            </div>
            
            <nav className="flex-1 px-3 py-6 space-y-1">
              <Link href="/" className="flex items-center px-3 py-2 text-sm font-medium rounded-lg text-neutral-400 hover:text-neutral-100 hover:bg-neutral-900/50 transition-colors">
                <HomeIcon className="w-4 h-4 mr-3" />
                Dashboard
              </Link>
              <Link href="/scans" className="flex items-center px-3 py-2 text-sm font-medium rounded-lg text-neutral-400 hover:text-neutral-100 hover:bg-neutral-900/50 transition-colors">
                <Search className="w-4 h-4 mr-3" />
                Scans
              </Link>
              <Link href="/targets" className="flex items-center px-3 py-2 text-sm font-medium rounded-lg text-neutral-400 hover:text-neutral-100 hover:bg-neutral-900/50 transition-colors">
                <Crosshair className="w-4 h-4 mr-3" />
                Targets
              </Link>
              <Link href="/integrations" className="flex items-center px-3 py-2 text-sm font-medium rounded-lg text-neutral-400 hover:text-neutral-100 hover:bg-neutral-900/50 transition-colors">
                <Blocks className="w-4 h-4 mr-3" />
                Integrations
              </Link>
              <Link href="/settings" className="flex items-center px-3 py-2 text-sm font-medium rounded-lg text-neutral-400 hover:text-neutral-100 hover:bg-neutral-900/50 transition-colors">
                <Settings className="w-4 h-4 mr-3" />
                Settings
              </Link>
            </nav>
          </aside>

          {/* Main Content Area */}
          <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
            {/* Top Navbar */}
            <header className="h-16 flex items-center justify-between px-8 border-b border-neutral-800/50 bg-[#09090b]">
              <div className="flex-1"></div>
              <div className="flex items-center space-x-4">
                <button className="w-8 h-8 rounded-full bg-neutral-900 border border-neutral-800 flex items-center justify-center text-xs font-medium text-neutral-300 hover:bg-neutral-800 transition-colors">
                  A
                </button>
                <button className="text-neutral-400 hover:text-neutral-200 transition-colors relative">
                  <Bell className="w-4 h-4" />
                  <span className="absolute top-0 right-0 w-1.5 h-1.5 bg-purple-500 rounded-full"></span>
                </button>
              </div>
            </header>

            {/* Page Content */}
            <div className="flex-1 overflow-auto p-8 lg:p-12">
              {children}
            </div>
          </main>
        </div>
      </body>
    </html>
  );
}
