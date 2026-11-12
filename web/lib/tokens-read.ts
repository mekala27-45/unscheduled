/**
 * Reads web/styles/tokens.css when the site is built, so the /design page prints each colour token's
 * light and dark value from the one file that defines them, and never a copy.
 */
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";

export type TokenPair = { name: string; light: string; dark: string };

const WEB_ROOT = existsSync(path.join(/*turbopackIgnore: true*/ process.cwd(), "next.config.ts")) ? process.cwd() : path.join(/*turbopackIgnore: true*/ process.cwd(), "web");

function block(css: string, selector: string): string {
  const start = css.indexOf(selector);
  if (start < 0) return "";
  const open = css.indexOf("{", start);
  let depth = 0;
  for (let i = open; i < css.length; i++) {
    if (css[i] === "{") depth++;
    else if (css[i] === "}" && --depth === 0) return css.slice(open + 1, i);
  }
  return "";
}

function declarations(body: string): Map<string, string> {
  const out = new Map<string, string>();
  const clean = body.replace(/\/\*[\s\S]*?\*\//g, "");
  for (const m of clean.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) out.set(m[1], m[2].trim());
  return out;
}

export function readColorTokens(): TokenPair[] {
  const css = readFileSync(path.join(/*turbopackIgnore: true*/ WEB_ROOT, "styles", "tokens.css"), "utf8");
  const light = declarations(block(css, ":root {"));
  const dark = declarations(block(css, ':root[data-theme="dark"]'));
  const out: TokenPair[] = [];
  for (const [name, value] of light) {
    if (!/^--(color|chart|seq|div|status)-/.test(name)) continue;
    out.push({ name, light: value, dark: dark.get(name) ?? value });
  }
  return out;
}
