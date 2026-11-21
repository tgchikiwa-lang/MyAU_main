import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";

const vectors = [
  { title: "", category: "Other", date: "", issuer: "", description: "" },
  { title: 'Quotes " and backslash \\', category: "Arts & Culture", date: "2026", issuer: "A/B", description: "tab\t newline\n return\r" },
  { title: "Unicode Māori 日本語 emoji 😀 🏅", category: "Academic", date: "春", issuer: "Université", description: "Résumé — Καλημέρα" },
  { title: "Controls \b\f\u0001", category: "Research", date: "", issuer: "", description: "line one\nline two\tend" },
];

const sql = vectors.map(item => {
  const json = JSON.stringify(item);
  let tag = "$iads$";
  while (json.includes(tag)) tag = `$iads${tag.length}$`;
  return `select public.au_achievement_hash(${tag}${json}${tag}::jsonb);`;
}).join("\n");

if (process.env.IADS_TEST_DB_CONFIRM !== "isolated-staging"
    || !process.env.PGHOST || !process.env.PGDATABASE || !process.env.PGUSER) {
  console.error("Set IADS_TEST_DB_CONFIRM=isolated-staging and the standard PGHOST, PGDATABASE, and PGUSER variables for an isolated staging database.");
  process.exit(2);
}

const result = spawnSync("psql", [
  "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1",
], { input: sql, encoding: "utf8", env: process.env });
if (result.error) {
  console.error(`Could not run psql: ${result.error.message}`);
  process.exit(2);
}
if (result.status !== 0) {
  console.error(result.stderr.trim() || "PostgreSQL hash comparison failed.");
  process.exit(result.status || 1);
}

const actual = result.stdout.trim().split(/\r?\n/);
if (actual.length !== vectors.length) {
  console.error(`Expected ${vectors.length} PostgreSQL hashes; received ${actual.length}.`);
  process.exit(1);
}
for (let i = 0; i < vectors.length; i++) {
  const item = vectors[i];
  const jsInput = JSON.stringify([
    "achievement",
    String(item.title ?? ""),
    String(item.category ?? ""),
    String(item.date ?? ""),
    String(item.issuer ?? ""),
    String(item.description ?? ""),
  ]);
  const expected = createHash("sha256").update(jsInput, "utf8").digest("hex");
  if (actual[i] !== expected) {
    console.error(`Hash mismatch for vector ${i + 1}: JS=${expected}; PostgreSQL=${actual[i]}`);
    process.exitCode = 1;
  }
}
if (!process.exitCode) console.log(`All ${vectors.length} JavaScript/PostgreSQL achievement hash vectors match.`);
