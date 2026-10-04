import js from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["node_modules", "artifacts", "cache", "src/deployers", "circuits"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      "prefer-arrow-callback": "error",
      "func-style": ["error", "expression"],
      "@typescript-eslint/no-unused-vars": ["error", { varsIgnorePattern: "^_", argsIgnorePattern: "^_" }],
    },
  },
);
