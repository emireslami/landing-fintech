const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const ADMIN_USERNAME = Deno.env.get('DASHBOARD_USERNAME')!;
const PASSWORD_SALT = Deno.env.get('DASHBOARD_PASSWORD_SALT')!;
const PASSWORD_HASH = Deno.env.get('DASHBOARD_PASSWORD_HASH')!;
const SESSION_SECRET = Deno.env.get('DASHBOARD_SESSION_SECRET')!;
const ALLOWED_ORIGINS = new Set([
  'https://mgmt.vibebuilders.ir',
  'http://127.0.0.1:8088',
  'http://localhost:8088',
]);

const encoder = new TextEncoder();
const json = (body: unknown, status = 200, origin = '') => new Response(JSON.stringify(body), {
  status,
  headers: {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': ALLOWED_ORIGINS.has(origin) ? origin : 'https://mgmt.vibebuilders.ir',
    'Access-Control-Allow-Headers': 'authorization, content-type',
    'Access-Control-Allow-Methods': 'GET, POST, PATCH, OPTIONS',
    'Vary': 'Origin',
  },
});

const toHex = (bytes: ArrayBuffer) => Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
const toBase64Url = (value: Uint8Array | string) => {
  const bytes = typeof value === 'string' ? encoder.encode(value) : value;
  let binary = '';
  bytes.forEach(byte => binary += String.fromCharCode(byte));
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};
const constantTimeEqual = (a: string, b: string) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
};
const hashPassword = async (password: string) => toHex(await crypto.subtle.digest('SHA-256', encoder.encode(`${PASSWORD_SALT}:${password}`)));
const sign = async (payload: string) => {
  const key = await crypto.subtle.importKey('raw', encoder.encode(SESSION_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toBase64Url(new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(payload))));
};
const createToken = async () => {
  const payload = toBase64Url(JSON.stringify({ sub: ADMIN_USERNAME, exp: Date.now() + 8 * 60 * 60 * 1000 }));
  return `${payload}.${await sign(payload)}`;
};
const verifyToken = async (header: string | null) => {
  const token = header?.startsWith('Bearer ') ? header.slice(7) : '';
  const [payload, signature] = token.split('.');
  if (!payload || !signature || !constantTimeEqual(signature, await sign(payload))) return false;
  try {
    const decoded = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    return decoded.sub === ADMIN_USERNAME && decoded.exp > Date.now();
  } catch { return false; }
};

const serviceRequest = async (path: string, init: RequestInit = {}) => fetch(`${SUPABASE_URL}${path}`, {
  ...init,
  headers: {
    apikey: SERVICE_KEY,
    Authorization: `Bearer ${SERVICE_KEY}`,
    ...(init.headers || {}),
  },
});

Deno.serve(async request => {
  const origin = request.headers.get('origin') || '';
  if (request.method === 'OPTIONS') return json({}, 200, origin);
  if (origin && !ALLOWED_ORIGINS.has(origin)) return json({ message: 'مبدأ درخواست مجاز نیست.' }, 403, origin);

  const url = new URL(request.url);
  const action = url.searchParams.get('action') || '';

  if (request.method === 'POST' && action === 'login') {
    const body = await request.json().catch(() => ({}));
    const validUser = constantTimeEqual(String(body.username || ''), ADMIN_USERNAME);
    const validPassword = constantTimeEqual(await hashPassword(String(body.password || '')), PASSWORD_HASH);
    if (!validUser || !validPassword) return json({ message: 'نام کاربری یا رمز عبور نادرست است.' }, 401, origin);
    return json({ token: await createToken() }, 200, origin);
  }

  if (!await verifyToken(request.headers.get('authorization'))) return json({ message: 'نشست شما معتبر نیست؛ دوباره وارد شوید.' }, 401, origin);

  if (request.method === 'GET' && action === 'applications') {
    const response = await serviceRequest('/rest/v1/bootcamp_applications?select=id,first_name,last_name,phone,resume_path,status,created_at,updated_at&order=created_at.desc');
    return json(response.ok ? await response.json() : { message: 'دریافت درخواست‌ها ناموفق بود.' }, response.status, origin);
  }

  if (request.method === 'PATCH' && action === 'status') {
    const body = await request.json().catch(() => ({}));
    const allowed = new Set(['unreviewed', 'initial_contact', 'awaiting_payment', 'scheduled', 'attended']);
    if (!body.id || !allowed.has(body.status)) return json({ message: 'درخواست نامعتبر است.' }, 400, origin);
    const response = await serviceRequest(`/rest/v1/bootcamp_applications?id=eq.${encodeURIComponent(body.id)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ status: body.status, updated_at: new Date().toISOString() }),
    });
    return json(response.ok ? { ok: true } : { message: 'به‌روزرسانی وضعیت ناموفق بود.' }, response.status, origin);
  }

  if (request.method === 'POST' && action === 'resume') {
    const body = await request.json().catch(() => ({}));
    if (!/^applications\/[0-9a-f-]+\.pdf$/i.test(String(body.path || ''))) return json({ message: 'مسیر رزومه نامعتبر است.' }, 400, origin);
    const encodedPath = body.path.split('/').map(encodeURIComponent).join('/');
    const response = await serviceRequest(`/storage/v1/object/sign/bootcamp-resumes/${encodedPath}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ expiresIn: 120 }),
    });
    const result = await response.json().catch(() => ({}));
    return json(response.ok ? { url: `${SUPABASE_URL}/storage/v1${result.signedURL}` } : { message: 'دریافت رزومه ناموفق بود.' }, response.status, origin);
  }

  return json({ message: 'مسیر پیدا نشد.' }, 404, origin);
});
