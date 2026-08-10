import { readFileSync, writeFileSync } from 'node:fs';

try {
	const pkg = JSON.parse(readFileSync('package.json', 'utf8'));
	const content = `// This file is auto-generated at build time by scripts/generate-version.js
export const name = ${JSON.stringify(pkg.name)};
export const version = ${JSON.stringify(pkg.version)};
`;
	writeFileSync('src/generated-version.ts', content, 'utf8');
	console.log('✓ src/generated-version.ts generated.');
} catch (err) {
	console.error('Error generating version:', err);
	process.exit(1);
}
