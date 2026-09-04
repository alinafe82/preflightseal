export function sanitizeEvidence(input: string, maxLength = 300): string {
  const withoutControls = input.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "?");
  if (withoutControls.length <= maxLength) {
    return withoutControls;
  }
  return `${withoutControls.slice(0, maxLength)}...`;
}
