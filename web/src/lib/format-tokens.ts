import type { BenchmarkTokenUsage } from "./types";

/** Format a raw token count concisely (e.g. 1.2M / 34.5k / 820). */
export function fmtTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

/** Build a human-readable breakdown string for tooltips and KPI subtitles. */
export function formatTokenBreakdown(tokens?: BenchmarkTokenUsage): string {
  if (!tokens) return "输入 0 · 输出 0 · 缓存 0";
  const cache = (tokens.cache_read_tokens ?? 0) + (tokens.cache_write_tokens ?? 0);
  return `输入 ${fmtTokens(tokens.input_tokens ?? 0)} · 输出 ${fmtTokens(tokens.output_tokens ?? 0)} · 缓存 ${fmtTokens(cache)}`;
}
