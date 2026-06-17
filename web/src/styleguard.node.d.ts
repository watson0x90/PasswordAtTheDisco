// Minimal ambient type slice for the node builtins used by styleguard.test.ts.
// This repo intentionally does not install @types/node (keeps the dependency
// surface tiny on a credential-bearing box). These declarations let the guard
// test type-check cleanly under `tsc --noEmit` without adding any dependency.
declare module "node:fs" {
  export function readdirSync(path: string): string[]
  export function readFileSync(path: string, encoding: "utf8"): string
  export function statSync(path: string): { isDirectory(): boolean }
}
declare module "node:path" {
  export function join(...parts: string[]): string
}
interface ImportMeta {
  readonly dirname: string
}
