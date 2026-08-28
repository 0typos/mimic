import type { DaemonStatus } from "mimic-caido-shared";

export function formatUptime(totalSeconds: number): string {
  const seconds = Math.max(0, Math.floor(totalSeconds));
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) {
    return `${days}d ${hours}h`;
  }
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  }
  return `${seconds}s`;
}

export function availableProfiles(status: DaemonStatus | null, override: string): string[] {
  const profiles = status === null ? [] : [...status.profiles];
  if (override !== "" && !profiles.includes(override)) {
    profiles.push(override);
  }
  return profiles.sort((left, right) => left.localeCompare(right));
}
