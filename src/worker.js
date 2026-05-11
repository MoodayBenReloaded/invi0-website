const REALM = "invi0";

function unauthorized() {
  return new Response("Authentication required.", {
    status: 401,
    headers: {
      "WWW-Authenticate": `Basic realm="${REALM}", charset="UTF-8"`,
      "Cache-Control": "no-store",
    },
  });
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

export default {
  async fetch(request, env) {
    const expectedUser = env.AUTH_USERNAME;
    const expectedPass = env.AUTH_PASSWORD;

    if (!expectedUser || !expectedPass) {
      return new Response(
        "Site is not configured: AUTH_USERNAME and AUTH_PASSWORD secrets are missing.",
        { status: 503, headers: { "Cache-Control": "no-store" } },
      );
    }

    const header = request.headers.get("Authorization");
    if (!header || !header.startsWith("Basic ")) return unauthorized();

    let decoded;
    try {
      decoded = atob(header.slice(6));
    } catch {
      return unauthorized();
    }

    const sep = decoded.indexOf(":");
    if (sep === -1) return unauthorized();
    const user = decoded.slice(0, sep);
    const pass = decoded.slice(sep + 1);

    const userOk = timingSafeEqual(user, expectedUser);
    const passOk = timingSafeEqual(pass, expectedPass);
    if (!userOk || !passOk) return unauthorized();

    return env.ASSETS.fetch(request);
  },
};
