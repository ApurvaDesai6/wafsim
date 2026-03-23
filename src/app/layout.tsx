import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "sonner";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "WAFSim - AWS WAF Testing Dashboard",
  description: "Visual AWS WAF testing and rule configuration dashboard. Build, test, and validate WAF rules before deploying to production.",
  keywords: ["AWS WAF", "Web Application Firewall", "Security", "Rule Testing", "Cloud Security"],
  authors: [{ name: "WAFSim Team" }],
  icons: {
    icon: "/logo.svg",
  },
  openGraph: {
    title: "WAFSim - AWS WAF Testing Dashboard",
    description: "Visual AWS WAF testing and rule configuration dashboard",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning className="dark">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-gray-950 text-white`}
      >
        {children}
        <Toaster position="bottom-right" theme="dark" />
      </body>
    </html>
  );
}
