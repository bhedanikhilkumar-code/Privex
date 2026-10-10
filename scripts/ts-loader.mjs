import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { stripTypeScriptTypes } from 'node:module';

function transformTypeScript(code) {
  // 1. Transform enums to const objects
  let transformed = code.replace(/(?:export\s+)?enum\s+([A-Za-z0-9_]+)\s*\{([^}]+)\}/g, (match, enumName, body) => {
    const isExport = match.trim().startsWith('export');
    const lines = body.split(',').map(s => s.trim()).filter(Boolean);
    const entries = lines.map(line => {
      const parts = line.split('=').map(p => p.trim());
      if (parts.length === 2) {
        return `${parts[0]}: ${parts[1]}`;
      } else {
        return `${parts[0]}: '${parts[0]}'`;
      }
    }).join(', ');
    return `${isExport ? 'export ' : ''}const ${enumName} = { ${entries} };`;
  });

  // 2. Add dummy const exports for exported interfaces and types so named imports don't fail in JS runtime
  const typeNames = [];
  const re = /export\s+(?:interface|type)\s+([A-Za-z0-9_]+)/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    typeNames.push(`export const ${m[1]} = {};`);
  }

  // 3. Strip TS types
  const stripped = stripTypeScriptTypes(transformed + '\n' + typeNames.join('\n'));
  return stripped;
}

export async function resolve(specifier, context, nextResolve) {
  if (specifier === '@private-protection/core') {
    return nextResolve(pathToFileURL(path.resolve('packages/core/src/index.ts')).href, context);
  }
  if (specifier === '@private-protection/ml') {
    return nextResolve(pathToFileURL(path.resolve('packages/ml/src/index.ts')).href, context);
  }
  
  if (specifier.startsWith('.') && !path.extname(specifier)) {
    try {
      const parentDir = path.dirname(fileURLToPath(context.parentURL));
      const candidateTs = path.join(parentDir, specifier + '.ts');
      if (fs.existsSync(candidateTs)) {
        return nextResolve(pathToFileURL(candidateTs).href, context);
      }
      const candidateIndex = path.join(parentDir, specifier, 'index.ts');
      if (fs.existsSync(candidateIndex)) {
        return nextResolve(pathToFileURL(candidateIndex).href, context);
      }
    } catch (e) {}
  }
  return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
  if (url.endsWith('.ts')) {
    const filePath = fileURLToPath(url);
    if (fs.existsSync(filePath)) {
      const source = fs.readFileSync(filePath, 'utf8');
      const js = transformTypeScript(source);
      return {
        format: 'module',
        source: js,
        shortCircuit: true
      };
    }
  }
  return nextLoad(url, context);
}
