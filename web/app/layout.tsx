import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "PQC Scan — Is Your Organization Quantum-Safe?",
  description: "Free instant post-quantum cryptography vulnerability scan. Check if your SSL certificates are ready for the quantum era.",
  openGraph: {
    title: "PQC Scan — Is Your Organization Quantum-Safe?",
    description: "Free instant PQC vulnerability scan for SSL certificates",
    type: "website",
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className={`${geistSans.variable} ${geistMono.variable} antialiased bg-zinc-950 text-zinc-100`}>
        {children}
      </body>
    </html>
  );
}
