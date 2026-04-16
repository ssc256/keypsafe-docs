import { defineConfig } from "vitepress";

export default defineConfig({
  title: "Keypsafe",
  description: "Encrypted backup and recovery for crypto wallets",

  head: [
    ["link", { rel: "icon", href: "/logo.svg", type: "image/svg+xml" }],
  ],

  themeConfig: {
    logo: "/logo.svg",

    nav: [
      { text: "Docs", link: "/overview" },
    ],

    sidebar: [
      {
        text: "Overview",
        link: "/overview",
      },
      {
        text: "Architecture",
        items: [
          { text: "System architecture", link: "/architecture/system-architecture" },
          { text: "Crypto architecture", link: "/architecture/crypto-architecture" },
          { text: "Key derivation", link: "/architecture/key-derivation" },
        ],
      },
      {
        text: "Security",
        items: [
          { text: "Security model", link: "/security/security-model" },
          { text: "Threat model", link: "/security/threat-model" },
        ],
      },
    ],

    socialLinks: [
      { icon: "github", link: "https://github.com/keypsafe" },
    ],

    search: {
      provider: "local",
    },

    footer: {
      message: "Client-side encrypted. Zero-knowledge by design.",
    },
  },
});
