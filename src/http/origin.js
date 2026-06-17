export function requestOrigin(request) {
  const host = singleHeader(request.headers.host);

  if (host === null) {
    return null;
  }

  const protocol = request.socket?.encrypted ? "https" : "http";

  return `${protocol}://${host}`;
}

export function singleHeader(header) {
  if (Array.isArray(header)) {
    return header.at(0) ?? null;
  }

  return header ?? null;
}
