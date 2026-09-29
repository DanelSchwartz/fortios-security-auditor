export default [
  {
    files: ["popup.js", "**/popup.js"],
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
        chrome: "readonly",
      },
    },
    rules: {
      "no-undef": "error",
      "no-useless-escape": "error",
      "no-unused-vars": ["warn", { "args": "none", "caughtErrors": "none", "varsIgnorePattern": "^(renderFinding|generate|check|run|setLanguage)" }],
    },
  },
];
