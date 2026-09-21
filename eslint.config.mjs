export default [
  {
    files: ["popup.js"],
    languageOptions: {
      sourceType: "script",
      globals: {
        window: "readonly",
        document: "readonly",
        navigator: "readonly",
        localStorage: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
        console: "readonly",
        FileReader: "readonly",
        Blob: "readonly",
        URL: "readonly",
        crypto: "readonly",
        TextEncoder: "readonly",
        Uint8Array: "readonly",
        ClipboardItem: "readonly",
      },
    },
    rules: {
      "no-undef": "error",
    },
  },
];
