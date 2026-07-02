const SUPABASE_URL = Deno.env.get('SUPABASE_URL')!;
const SERVICE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const LOOKUP_SALT = Deno.env.get('STATUS_LOOKUP_SALT')!;
const ALLOWED_ORIGINS = new Set([
  'https://vibebuilders.ir',
  'https://www.vibebuilders.ir',
  'http://127.0.0.1:8088',
  'http://localhost:8088',
]);

const json = (body: unknown, status: number, origin: string) => new Response(JSON.stringify(body), {
  status,
  headers: {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Access-Control-Allow-Origin': ALLOWED_ORIGINS.has(origin) ? origin : 'https://vibebuilders.ir',
    'Access-Control-Allow-Headers': 'content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Vary': 'Origin',
  },
});

const hash = async (value: string) => Array.from(
  new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`${LOOKUP_SALT}:${value}`))),
  byte => byte.toString(16).padStart(2, '0'),
).join('');

Deno.serve(async request => {
  const origin = request.headers.get('origin') || '';
  if (request.method === 'OPTIONS') return json({}, 200, origin);
  if (origin && !ALLOWED_ORIGINS.has(origin)) return json({ message: 'مبدأ درخواست مجاز نیست.' }, 403, origin);
  if (request.method !== 'POST') return json({ message: 'متد درخواست مجاز نیست.' }, 405, origin);

  const body = await request.json().catch(() => ({}));
  const phone = String(body.phone || '');
  if (!/^\+989[0-9]{9}$/.test(phone)) return json({ message: 'شماره موبایل معتبر نیست.' }, 400, origin);

  const forwarded = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim();
  const clientIp = request.headers.get('cf-connecting-ip') || forwarded || 'unknown';
  const lookupKey = await hash(clientIp);
  const response = await fetch(`${SUPABASE_URL}/rest/v1/rpc/lookup_application_status`, {
    method: 'POST',
    headers: {
      apikey: SERVICE_KEY,
      Authorization: `Bearer ${SERVICE_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ p_phone: phone, p_lookup_key: lookupKey }),
  });

  const result = await response.json().catch(() => null);
  if (!response.ok) {
    const limited = result?.message === 'rate_limit';
    return json({ message: limited ? 'تعداد درخواست‌ها بیش از حد مجاز است؛ ۱۵ دقیقه دیگر تلاش کنید.' : 'پیگیری وضعیت در حال حاضر ممکن نیست.' }, limited ? 429 : 502, origin);
  }
  return json({ found: Boolean(result), status: result || null }, 200, origin);
});
