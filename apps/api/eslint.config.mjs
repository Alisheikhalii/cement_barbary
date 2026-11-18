import baseConfig from '@bitabar/config/eslint';

export default [
  ...baseConfig,
  {
    rules: {
      // NestJS modules are decorator-driven empty classes by design.
      '@typescript-eslint/no-extraneous-class': ['error', { allowWithDecorator: true }],
    },
  },
];
