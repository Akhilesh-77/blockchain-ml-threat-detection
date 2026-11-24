import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CyberNex | AI-Powered Android Security Simulation & Blockchain Platform",
  description: "AI-Powered Android Security Simulation, Machine Learning Threat Detection & Blockchain Auditing Platform",
  icons: {
    icon: "/favicon.ico",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#0B0F19] text-slate-100 antialiased min-h-screen">
        {children}
      </body>
    </html>
  );
}
