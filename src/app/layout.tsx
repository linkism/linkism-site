import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Linkism Protocol",
  description: "RFC Spec v1.0 – Persistent UI element identity. No more brittle selectors.",
  openGraph: {
    title: "Linkism Protocol - Persistent UI Element Identity",
    description: "RFC Spec v1.0 – Solve brittle selectors with lid:// addresses that survive redesigns, framework migrations, and DOM changes.",
    url: "https://linkism.org",
    siteName: "Linkism Protocol",
    images: [
      {
        url: "/og-image.png",
        width: 1200,
        height: 630,
        alt: "Linkism Protocol",
        type: "image/png",
      },
    ],
    locale: "en_US",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Linkism Protocol",
    description: "RFC Spec v1.0 – No more brittle selectors.",
    images: ["/og-image.png"],
  },
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "any" },
      { url: "/icon.svg", type: "image/svg+xml" },
    ],
    apple: "/apple-touch-icon.png",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}
