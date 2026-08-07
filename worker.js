// ═══════════════════════════════════════════════════════════════════
// Adrenalin coaching portal — API worker
//
// Serves the static app (index.html) and everything under /api/*.
// This worker holds NO hardcoded secrets: KV is reached through a
// binding (env.ADRENALIN_KV), not a Cloudflare API token, and session
// tokens are opaque random values stored in KV — nothing here needs to
// be embedded in code or shipped to the browser.
//
// Every /api/kv request is scoped to the caller's own data: a client
// session can only read/write keys whose owner segment is their own
// username; only an admin session can touch another client's keys or
// the admin-only global keys (clientList, dylan-*, etc). That scoping
// is the actual fix — the old adrenalin-kv worker had a single shared
// token that granted full read/write access to every client's data.
// ═══════════════════════════════════════════════════════════════════

const SESSION_TTL_SECONDS = 60 * 60 * 24 * 30; // 30 days — persistent login
const PBKDF2_ITERATIONS = 100000;

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { 'Content-Type': 'application/json' }
  });
}

// ── base64 helpers (Workers runtime has btoa/atob but not Buffer) ──
function bytesToB64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function b64url(bytes) {
  return bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ── password hashing (PBKDF2-SHA256, per-user random salt) ──
async function hashPassword(password, saltB64) {
  const salt = saltB64 ? b64ToBytes(saltB64) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return { salt: bytesToB64(salt), hash: bytesToB64(new Uint8Array(bits)) };
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// ── sessions ──
function generateToken() {
  return b64url(crypto.getRandomValues(new Uint8Array(32)));
}
function getBearerToken(request) {
  const auth = request.headers.get('Authorization') || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : null;
}
async function requireAuth(request, env) {
  const token = getBearerToken(request);
  if (!token) return null;
  const raw = await env.ADRENALIN_KV.get('session:' + token);
  if (!raw) return null;
  try { return JSON.parse(raw); } catch (e) { return null; }
}

// ── shared: a client's profile merged with their authoritative session history ──
// (mirrors what the old client-side hydration used to do across two KV reads)
async function getMergedProfile(env, username) {
  const [profileRaw, sessionsRaw] = await Promise.all([
    env.ADRENALIN_KV.get('profile:' + username),
    env.ADRENALIN_KV.get('sessions:' + username)
  ]);
  if (!profileRaw) return null;
  const profile = JSON.parse(profileRaw);
  if (sessionsRaw) {
    try {
      const sessions = JSON.parse(sessionsRaw);
      if (Array.isArray(sessions)) profile.sessions_history = sessions;
    } catch (e) { /* ignore malformed sessions blob, keep profile's own copy */ }
  }
  return profile;
}

// ── ownership scoping for the generic KV proxy ──
const OWNED_PREFIXES = /^(checkins|daytemplates|food|messages|mymeals|profile|sessions):/;
function canAccessKey(key, session) {
  if (session.role === 'admin') return true;
  if (!OWNED_PREFIXES.test(key)) return false; // clientList, client:*, dylan-* etc — admin only
  const rest = key.slice(key.indexOf(':') + 1);
  return rest === session.username || rest.startsWith(session.username + '_');
}

// ── endpoint handlers ──
async function handleLogin(request, env) {
  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'Invalid JSON' }, 400); }
  const username = String(body.username || '').trim().toLowerCase();
  const password = String(body.password || '');
  if (!username || !password) return json({ error: 'Missing username or password' }, 400);

  const credsRaw = await env.ADRENALIN_KV.get('authcreds:' + username);
  if (!credsRaw) return json({ error: 'Invalid username or password' }, 401);
  const creds = JSON.parse(credsRaw);
  const { hash } = await hashPassword(password, creds.salt);
  if (!timingSafeEqual(hash, creds.hash)) return json({ error: 'Invalid username or password' }, 401);

  const token = generateToken();
  await env.ADRENALIN_KV.put(
    'session:' + token,
    JSON.stringify({ username, role: creds.role }),
    { expirationTtl: SESSION_TTL_SECONDS }
  );

  const profile = creds.role === 'client' ? await getMergedProfile(env, username) : null;
  return json({ token, username, role: creds.role, profile });
}

async function handleMe(request, env) {
  const session = await requireAuth(request, env);
  if (!session) return json({ error: 'Unauthorised' }, 401);
  const profile = session.role === 'client' ? await getMergedProfile(env, session.username) : null;
  return json({ username: session.username, role: session.role, profile });
}

async function handleLogout(request, env) {
  const token = getBearerToken(request);
  if (token) await env.ADRENALIN_KV.delete('session:' + token);
  return json({ ok: true });
}

async function handleGetClients(request, env) {
  const session = await requireAuth(request, env);
  if (!session || session.role !== 'admin') return json({ error: 'Forbidden' }, 403);

  const listRaw = await env.ADRENALIN_KV.get('clientList');
  const usernames = listRaw ? JSON.parse(listRaw) : [];
  const clients = {};
  await Promise.all(usernames.map(async (u) => {
    const profile = await getMergedProfile(env, u);
    if (profile) clients[u] = profile;
  }));
  return json({ clients });
}

async function handleCreateClient(request, env) {
  const session = await requireAuth(request, env);
  if (!session || session.role !== 'admin') return json({ error: 'Forbidden' }, 403);

  let body;
  try { body = await request.json(); } catch (e) { return json({ error: 'Invalid JSON' }, 400); }
  const username = String(body.username || '').trim().toLowerCase();
  const password = String(body.password || '');
  const profile = body.profile;
  if (!username || !password || !profile) return json({ error: 'Missing username, password, or profile' }, 400);

  const existing = await env.ADRENALIN_KV.get('authcreds:' + username);
  if (existing) return json({ error: 'Username already exists' }, 409);

  const { salt, hash } = await hashPassword(password);
  await env.ADRENALIN_KV.put('authcreds:' + username, JSON.stringify({ salt, hash, role: 'client' }));
  await env.ADRENALIN_KV.put('profile:' + username, JSON.stringify(profile));

  const listRaw = await env.ADRENALIN_KV.get('clientList');
  const list = listRaw ? JSON.parse(listRaw) : [];
  if (!list.includes(username)) list.push(username);
  await env.ADRENALIN_KV.put('clientList', JSON.stringify(list));

  return json({ ok: true, username });
}

async function handleKv(request, env) {
  const session = await requireAuth(request, env);
  if (!session) return json({ error: 'Unauthorised' }, 401);

  const url = new URL(request.url);

  if (request.method === 'GET') {
    const key = url.searchParams.get('key');
    if (!key) return json({ error: 'Missing key' }, 400);
    if (!canAccessKey(key, session)) return json({ error: 'Forbidden' }, 403);
    const raw = await env.ADRENALIN_KV.get(key);
    let value = null;
    if (raw !== null) { try { value = JSON.parse(raw); } catch (e) { value = raw; } }
    return json({ key, value });
  }

  if (request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch (e) { return json({ error: 'Invalid JSON' }, 400); }
    const { key, value, action } = body;
    if (!key) return json({ error: 'Missing key' }, 400);
    if (!canAccessKey(key, session)) return json({ error: 'Forbidden' }, 403);

    let finalValue = value;
    if (action === 'append') {
      const existingRaw = await env.ADRENALIN_KV.get(key);
      let arr = [];
      if (existingRaw) { try { arr = JSON.parse(existingRaw); } catch (e) { arr = []; } }
      if (!Array.isArray(arr)) arr = [];
      arr.unshift(value);
      finalValue = arr;
    }

    await env.ADRENALIN_KV.put(key, JSON.stringify(finalValue));
    return json({ key, value: finalValue });
  }

  if (request.method === 'DELETE') {
    const key = url.searchParams.get('key');
    if (!key) return json({ error: 'Missing key' }, 400);
    if (!canAccessKey(key, session)) return json({ error: 'Forbidden' }, 403);
    await env.ADRENALIN_KV.delete(key);
    return json({ deleted: key });
  }

  return json({ error: 'Method not allowed' }, 405);
}

async function handleApi(request, env) {
  const path = new URL(request.url).pathname;

  if (path === '/api/login' && request.method === 'POST') return handleLogin(request, env);
  if (path === '/api/me' && request.method === 'GET') return handleMe(request, env);
  if (path === '/api/logout' && request.method === 'POST') return handleLogout(request, env);
  if (path === '/api/clients' && request.method === 'GET') return handleGetClients(request, env);
  if (path === '/api/clients' && request.method === 'POST') return handleCreateClient(request, env);
  if (path === '/api/kv') return handleKv(request, env);

  return json({ error: 'Not found' }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      try {
        return await handleApi(request, env);
      } catch (e) {
        return json({ error: 'Internal error', detail: String((e && e.message) || e) }, 500);
      }
    }
    return env.ASSETS.fetch(request);
  }
};
