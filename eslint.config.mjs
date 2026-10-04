import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['**/dist/**', '**/out/**', '**/node_modules/**', '**/media/**', '**/test/fixtures/**', '**/.vscode-test/**', 'vsix/**'] },
  ...tseslint.configs.recommended,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
      curly: 'warn',
      eqeqeq: 'warn',
    },
  },
);
