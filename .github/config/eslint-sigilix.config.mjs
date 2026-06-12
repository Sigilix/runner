import security from "eslint-plugin-security";
import tseslint from "typescript-eslint";
import unicorn from "eslint-plugin-unicorn";

const typedTsconfig = process.env.SIGILIX_ESLINT_TSCONFIG || "";

const commonGlobals = {
  AbortController: "readonly",
  Blob: "readonly",
  Buffer: "readonly",
  URL: "readonly",
  URLSearchParams: "readonly",
  __dirname: "readonly",
  __filename: "readonly",
  clearInterval: "readonly",
  clearTimeout: "readonly",
  console: "readonly",
  document: "readonly",
  exports: "readonly",
  fetch: "readonly",
  global: "readonly",
  globalThis: "readonly",
  module: "readonly",
  process: "readonly",
  require: "readonly",
  setInterval: "readonly",
  setTimeout: "readonly",
  window: "readonly",
};

const jsFiles = ["**/*.{js,jsx,mjs,cjs}"];
const tsFiles = ["**/*.{ts,tsx,mts,cts}"];

const commonRules = {
  "no-async-promise-executor": "error",
  "no-promise-executor-return": "error",
  "no-unreachable": "error",
  "no-unsafe-finally": "error",
  "security/detect-eval-with-expression": "error",
  "security/detect-new-buffer": "error",
  "security/detect-unsafe-regex": "warn",
  "unicorn/no-instanceof-builtins": "error",
};

const config = tseslint.config(
  {
    ignores: [
      "**/.git/**",
      "**/.next/**",
      "**/.pytest_cache/**",
      "**/.terraform/**",
      "**/.tox/**",
      "**/.venv/**",
      "**/__pycache__/**",
      "**/build/**",
      "**/coverage/**",
      "**/dist/**",
      "**/node_modules/**",
      "**/out/**",
      "**/vendor/**",
    ],
  },
  {
    files: jsFiles,
    languageOptions: {
      ecmaVersion: "latest",
      globals: commonGlobals,
      sourceType: "module",
    },
    plugins: { security, unicorn },
    rules: {
      ...commonRules,
      "no-undef": "error",
    },
  },
  {
    files: tsFiles,
    languageOptions: {
      ecmaVersion: "latest",
      globals: commonGlobals,
      parser: tseslint.parser,
      parserOptions: {
        jsDocParsingMode: "none",
        sourceType: "module",
      },
      sourceType: "module",
    },
    plugins: {
      "@typescript-eslint": tseslint.plugin,
      security,
      unicorn,
    },
    rules: {
      ...commonRules,
      "@typescript-eslint/no-duplicate-enum-values": "error",
      "@typescript-eslint/no-extra-non-null-assertion": "error",
      "@typescript-eslint/no-non-null-asserted-optional-chain": "error",
      "@typescript-eslint/no-unsafe-declaration-merging": "error",
    },
  },
);

if (typedTsconfig) {
  config.push({
    files: tsFiles,
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        jsDocParsingMode: "none",
        project: typedTsconfig,
        sourceType: "module",
        tsconfigRootDir: process.cwd(),
      },
    },
    plugins: {
      "@typescript-eslint": tseslint.plugin,
    },
    rules: {
      "@typescript-eslint/await-thenable": "error",
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": ["error", { checksVoidReturn: { attributes: false } }],
    },
  });
}

export default config;
