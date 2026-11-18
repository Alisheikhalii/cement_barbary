// Conventional Commits (GUIDELINES §9) + the extra `security` type.
export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      [
        'feat',
        'fix',
        'docs',
        'refactor',
        'test',
        'chore',
        'perf',
        'security',
        'ci',
        'build',
        'style',
        'revert',
      ],
    ],
  },
};
