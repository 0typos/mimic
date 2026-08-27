export function createPreface(target: string, tls: boolean, profile: string): string {
  return `MIMIC/1 ${JSON.stringify({ target, tls, profile })}\n`;
}
