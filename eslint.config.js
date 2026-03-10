import tsParser from "@typescript-eslint/parser";

export default [
  {
    ignores: [
      "node_modules/**",
      "dist/**",
      "build/**",
      "coverage/**",
      ".opensecurity/**"
    ]
  },
  {
    files: ["**/*.{js,cjs,mjs,ts,tsx}"] ,
    languageOptions: {
      parser: tsParser,
      ecmaVersion: "latest",
      sourceType: "module"
    },
    rules: {}
  }
];
