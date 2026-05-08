#!/usr/bin/env node
/**
 * scripts/validate-index-html.mjs
 *
 * Garde-fou syntaxe pour index.html :
 *  - Extrait chaque bloc <script> inline (sans src=)
 *  - Valide la syntaxe JavaScript via `node --check`
 *  - Détecte les occurrences de </script> à l'intérieur du code JS
 *    (dangereux dans les template strings — casse le parsing HTML)
 *  - Échoue avec un message clair si l'un des blocs ne parse pas
 *
 * Usage : node scripts/validate-index-html.mjs
 */

import { readFileSync, writeFileSync, unlinkSync } from 'fs';
import { execFileSync } from 'child_process';
import { randomUUID } from 'crypto';
import { tmpdir } from 'os';
import { join, resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const indexPath = resolve(__dirname, '..', 'index.html');

// ── Read file ────────────────────────────────────────────────────────────────

let html;
try {
  html = readFileSync(indexPath, 'utf-8');
} catch (err) {
  console.error(`❌ Impossible de lire index.html : ${err.message}`);
  process.exit(1);
}

const lines = html.split('\n');

// ── Extract inline <script> blocks ──────────────────────────────────────────
// Rules:
//  - Ignore <script src="..."> (external scripts)
//  - Collect content between opening <script> tag and its closing </script>
//  - Record start/end line numbers for accurate error reporting

const scriptBlocks = [];
let i = 0;

while (i < lines.length) {
  const line = lines[i];

  // Match an opening <script …> that is NOT an external script (no src=)
  const openMatch = /<script(\s[^>]*)?>/i.exec(line);
  if (openMatch && !/\bsrc\s*=/i.test(openMatch[0])) {
    const attrs = openMatch[1] || '';
    const isModule = /type\s*=\s*["']module["']/i.test(attrs);

    // The content starts on the next line (line numbers are 1-based)
    const contentStartLine = i + 2; // 1-based line of first content line
    const rawLines = [];
    i++;

    while (i < lines.length) {
      if (/<\/script>/i.test(lines[i])) {
        break;
      }
      rawLines.push(lines[i]);
      i++;
    }

    // The line at index i is the line that contains </script>.
    // If </script> is NOT alone on that line (has JS content before it),
    // the script was cut short inside a template string or expression.
    const closingLine = lines[i] || '';
    const closeMatch = /<\/script>/i.exec(closingLine);
    const beforeClose = closeMatch ? closingLine.slice(0, closeMatch.index).trim() : '';
    const closingLineNum = i + 1; // 1-based

    const contentEndLine = i; // 0-based index of closing </script> line
    scriptBlocks.push({
      startLine: contentStartLine,
      endLine: contentEndLine,
      code: rawLines.join('\n'),
      isModule,
      // Signal if </script> was found mid-line (probable template string issue)
      dangerousCloseOnLine: beforeClose.length > 0 ? closingLineNum : null,
    });
  }

  i++;
}

if (scriptBlocks.length === 0) {
  console.warn('⚠️  Aucun bloc <script> inline trouvé dans index.html.');
  process.exit(0);
}

console.log(`🔍 ${scriptBlocks.length} bloc(s) <script> inline détecté(s) dans index.html\n`);

// ── Validate each block ──────────────────────────────────────────────────────

let hasError = false;

for (const block of scriptBlocks) {
  const { startLine, code, isModule, dangerousCloseOnLine } = block;
  const blockDesc = `bloc <script${isModule ? ' type="module"' : ''}> (ligne ${startLine})`;

  // 1. Check for </script> appearing mid-line inside the script region.
  //    The HTML parser always treats the FIRST </script> as the block's end,
  //    so if </script> is inside a template string the script is silently
  //    truncated, corrupting both the JS and the surrounding HTML.
  if (dangerousCloseOnLine !== null) {
    console.error(
      `❌ [${blockDesc}] Séquence dangereuse "</script>" à la ligne ${dangerousCloseOnLine} :\n` +
        `   Le parser HTML clôt le bloc <script> dès le premier </script> rencontré.\n` +
        `   Si c'est dans une template string, remplacer par "<" + "/script" ou "\\u003c/script".`
    );
    hasError = true;
  }

  // Also check inside the already-extracted code for any </script that might
  // have snuck through (should be rare but covers edge cases in the extractor).
  const dangerPattern = /<\/script/gi;
  let match;
  while ((match = dangerPattern.exec(code)) !== null) {
    const offsetLine =
      startLine + code.slice(0, match.index).split('\n').length - 1;
    console.error(
      `❌ [${blockDesc}] Séquence dangereuse "</script" à la ligne ~${offsetLine} :\n` +
        `   Remplacer par "<" + "/script" ou "\\u003c/script" si nécessaire.`
    );
    hasError = true;
  }

  // 2. Syntax check via `node --check`
  //    Write to a temp file so Node can report accurate line numbers.
  //    Use .mjs for modules, .js for classic scripts.
  const ext = isModule ? 'mjs' : 'js';
  const tmpFile = join(tmpdir(), `taskafe-validate-${randomUUID()}.${ext}`);

  try {
    writeFileSync(tmpFile, code, 'utf-8');
    execFileSync(process.execPath, ['--check', tmpFile], { stdio: 'pipe' });
    console.log(`✅ ${blockDesc} — syntaxe OK`);
  } catch (err) {
    hasError = true;
    // Node --check writes to stderr; adjust reported line numbers
    // (Node reports lines relative to the temp file starting at 1,
    //  we add startLine - 1 so the number maps back to index.html)
    const raw = (err.stderr || Buffer.alloc(0)).toString('utf-8');
    const adjusted = raw.replace(
      new RegExp(tmpFile.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ':(\\d+)', 'g'),
      (_, n) => `index.html:${Number(n) + startLine - 1}`
    );
    console.error(`❌ Erreur de syntaxe dans ${blockDesc} :`);
    console.error(adjusted || err.message);
  } finally {
    try { unlinkSync(tmpFile); } catch { /* ignore */ }
  }
}

// ── Final result ─────────────────────────────────────────────────────────────

if (hasError) {
  console.error('\n❌ Validation échouée — index.html contient des erreurs JavaScript.');
  process.exit(1);
} else {
  console.log('\n✅ Validation réussie — tous les blocs <script> de index.html sont syntaxiquement corrects.');
  process.exit(0);
}
