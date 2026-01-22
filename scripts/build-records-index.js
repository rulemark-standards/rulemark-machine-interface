#!/usr/bin/env node
/**
 * scripts/build-records-index.js
 *
 * Scan `records/` for all PDF files and generate a minimal `records/index.html`
 * containing each PDF filename and a download link.
 *
 * Only Node.js built-ins are used: fs, path.
 */

const fs = require("node:fs");
const path = require("node:path");

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function walkPdfs(dirAbs, baseAbs, outRelPaths) {
  const entries = fs.readdirSync(dirAbs, { withFileTypes: true });
  for (const ent of entries) {
    const fullAbs = path.join(dirAbs, ent.name);
    if (ent.isDirectory()) {
      walkPdfs(fullAbs, baseAbs, outRelPaths);
      continue;
    }
    if (ent.isFile() && ent.name.toLowerCase().endsWith(".pdf")) {
      const rel = path.relative(baseAbs, fullAbs);
      // Normalize for browser hrefs on Windows/macOS/Linux.
      outRelPaths.push(rel.split(path.sep).join("/"));
    }
  }
}

function main() {
  const repoRoot = path.resolve(__dirname, "..");
  const recordsDir = path.join(repoRoot, "records");

  if (!fs.existsSync(recordsDir) || !fs.statSync(recordsDir).isDirectory()) {
    throw new Error(`records/ directory not found: ${recordsDir}`);
  }

  const pdfRelPaths = [];
  walkPdfs(recordsDir, recordsDir, pdfRelPaths);
  pdfRelPaths.sort((a, b) => a.localeCompare(b, "en"));

  const listHtml =
    pdfRelPaths.length === 0
      ? "<p>No PDFs found.</p>"
      : `<ul>
${pdfRelPaths
  .map((rel) => {
    const filename = path.posix.basename(rel);
    const href = encodeURI(rel);
    return `  <li>${escapeHtml(filename)} — <a href="${href}" download>Download</a></li>`;
  })
  .join("\n")}
</ul>`;

  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Records</title>
  </head>
  <body>
    <h1>Records</h1>
    ${listHtml}
  </body>
</html>
`;

  fs.writeFileSync(path.join(recordsDir, "index.html"), html, "utf8");
}

try {
  main();
} catch (err) {
  console.error(err);
  process.exitCode = 1;
}

