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
  title: "AWS WAFSim - Rule Testing & Validation",
  description: "Interactive AWS WAF rule simulator. Build, test, and validate WebACL configurations against real attack patterns before deploying to production.",
  keywords: ["AWS WAF", "Web Application Firewall", "Security", "Rule Testing", "Cloud Security"],
  authors: [{ name: "Apurva Desai" }],
  icons: {
    icon: "/favicon.svg",
  },
  openGraph: {
    title: "AWS WAFSim - Rule Testing & Validation",
    description: "Interactive AWS WAF rule simulator for testing WebACL configurations",
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
