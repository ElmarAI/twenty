// SPDX-License-Identifier: AGPL-3.0-only
const fs = require('node:fs');
const path = require('node:path');
const ts = require('/app/node_modules/typescript');
const sourceRoot = '/oidc-source';
const outputRoot = '/app/packages/twenty-server/dist';
const files = [
  'engine/core-modules/auth/auth.module.ts',
  'engine/core-modules/auth/community-oidc/community-oidc-flow.ts',
  'engine/core-modules/auth/community-oidc/community-oidc.controller.ts',
  'engine/core-modules/workspace/types/workspace.type.ts',
];
for (const file of files) {
  let source = fs.readFileSync(path.join(sourceRoot, file), 'utf8');
  if (source.includes('@license Enterprise'))
    throw new Error(`Enterprise source must remain unchanged: ${file}`);
  source = source.replace(/from 'src\/([^']+)'/g, (_, target) => {
    let relative = path.relative(path.dirname(file), target);
    if (!relative.startsWith('.')) relative = './' + relative;
    return `from '${relative}'`;
  });
  const result = ts.transpileModule(source, {
    fileName: file,
    reportDiagnostics: true,
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      experimentalDecorators: true,
      emitDecoratorMetadata: true,
      esModuleInterop: true,
    },
  });
  if (
    result.diagnostics.some(
      (item) => item.category === ts.DiagnosticCategory.Error,
    )
  )
    throw new Error(`Compile failed: ${file}`);
  const output = path.join(outputRoot, file.replace(/\.ts$/, '.js'));
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, result.outputText);
}
const modulesLink = path.join(sourceRoot, 'node_modules');
if (!fs.existsSync(modulesLink))
  fs.symlinkSync('/app/node_modules', modulesLink, 'dir');
const program = ts.createProgram(
  [
    path.join(
      sourceRoot,
      'engine/core-modules/auth/community-oidc/community-oidc-flow.ts',
    ),
  ],
  {
    noEmit: true,
    strict: true,
    skipLibCheck: true,
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.CommonJS,
    moduleResolution: ts.ModuleResolutionKind.Node10,
    esModuleInterop: true,
    types: ['node'],
    typeRoots: ['/app/node_modules/@types'],
  },
);
const diagnostics = ts.getPreEmitDiagnostics(program);
if (diagnostics.length) {
  console.error(
    ts.formatDiagnosticsWithColorAndContext(diagnostics, {
      getCanonicalFileName: (file) => file,
      getCurrentDirectory: () => sourceRoot,
      getNewLine: () => '\n',
    }),
  );
  process.exit(1);
}
