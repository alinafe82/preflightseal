export function sanitizeEvidence(input: string, maxLength = 300): string {
  const redacted = input
    .replace(/\b[A-Za-z0-9_=-]*(?:token|secret|key)[A-Za-z0-9_=-]*[:=][^\s"'`]+/gi, "[REDACTED]")
    .replace(/\b(?:sk|ghp|github_pat|npm)[_-][A-Za-z0-9_=-]{12,}\b/g, "[REDACTED]");
  const withoutControls = redacted.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "?");
  if (withoutControls.length <= maxLength) {
    return withoutControls;
  }
  return `${withoutControls.slice(0, maxLength)}...`;
}
