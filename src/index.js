const MAX_BYTES = 100 * 1024 * 1024;
const MAX_REDIRECTS = 5;
const FETCH_TIMEOUT_MS = 25000;
const CACHE_TTL_SECONDS = 3600;

const ALLOWED_TYPES = [
  'application/pdf',
  'application/x-pdf',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'application/octet-stream',
  'binary/octet-stream'
];

const ALLOWED_EXTENSIONS = ['.pdf', '.pptx'];

function parseAllowedOrigins(env) {
  const raw = (env.ALLOWED_ORIGINS || '*').trim();
  if (raw === '*') return null;
  return raw.split(',').map((s) => s.trim()).filter(Boolean);
}

function corsHeaders(request, env) {
  const allowed = parseAllowedOrigins(env);
  const origin = request.headers.get('Origin') || '';
  const headers = new Headers({
    'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Expose-Headers': 'Content-Length, Content-Type, X-Final-Url',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin'
  });
  if (allowed === null) {
    headers.set('Access-Control-Allow-Origin', '*');
  } else if (origin && allowed.includes(origin)) {
    headers.set('Access-Control-Allow-Origin', origin);
  }
  return headers;
}

function isOriginAllowed(request, env) {
  const allowed = parseAllowedOrigins(env);
  if (allowed === null) return true;
  const origin = request.headers.get('Origin');
  return !!origin && allowed.includes(origin);
}

function errorResponse(status, message, cors) {
  const headers = new Headers(cors);
  headers.set('Content-Type', 'application/json; charset=utf-8');
  headers.set('Cache-Control', 'no-store');
  return new Response(JSON.stringify({ error: message }), { status, headers });
}

function isPrivateIPv4(host) {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 192 && b === 0) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a >= 224) return true;
  return false;
}

function isPrivateIPv6(host) {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (!h.includes(':')) return false;
  if (h === '::' || h === '::1') return true;
  if (h.startsWith('fc') || h.startsWith('fd')) return true;
  if (h.startsWith('fe8') || h.startsWith('fe9') || h.startsWith('fea') || h.startsWith('feb')) return true;
  if (h.startsWith('::ffff:')) return true;
  return false;
}

function validateTarget(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch (_) {
    return { error: 'Invalid URL' };
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return { error: 'Only http and https URLs are supported' };
  }
  if (url.username || url.password) {
    return { error: 'URLs with credentials are not allowed' };
  }
  const host = url.hostname.toLowerCase();
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal') ||
    host.endsWith('.lan') ||
    host.endsWith('.home.arpa') ||
    isPrivateIPv4(host) ||
    isPrivateIPv6(host)
  ) {
    return { error: 'Target host is not allowed' };
  }
  if (url.port && !['80', '443', '8080', '8443'].includes(url.port)) {
    return { error: 'Target port is not allowed' };
  }
  return { url };
}

function hasAllowedExtension(url) {
  const path = url.pathname.toLowerCase();
  return ALLOWED_EXTENSIONS.some((ext) => path.endsWith(ext));
}

function isAllowedContentType(contentType) {
  const type = (contentType || '').split(';')[0].trim().toLowerCase();
  return ALLOWED_TYPES.includes(type);
}

async function fetchWithRedirects(startUrl, signal) {
  let current = startUrl;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const response = await fetch(current.toString(), {
      method: 'GET',
      redirect: 'manual',
      signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; PDFSlideViewerProxy/1.0)',
        'Accept': 'application/pdf,application/vnd.openxmlformats-officedocument.presentationml.presentation,*/*;q=0.5'
      },
      cf: { cacheTtl: CACHE_TTL_SECONDS, cacheEverything: true }
    });
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('Location');
      if (!location) return { error: 'Redirect without location', status: 502 };
      let next;
      try {
        next = new URL(location, current);
      } catch (_) {
        return { error: 'Invalid redirect location', status: 502 };
      }
      const checked = validateTarget(next.toString());
      if (checked.error) return { error: checked.error, status: 403 };
      current = checked.url;
      continue;
    }
    return { response, finalUrl: current };
  }
  return { error: 'Too many redirects', status: 508 };
}

function limitStream(body, maxBytes) {
  let total = 0;
  const limiter = new TransformStream({
    transform(chunk, controller) {
      total += chunk.byteLength;
      if (total > maxBytes) {
        controller.error(new Error('Payload too large'));
        return;
      }
      controller.enqueue(chunk);
    }
  });
  return body.pipeThrough(limiter);
}

export default {
  async fetch(request, env) {
    const cors = corsHeaders(request, env);

    if (request.method === 'OPTIONS') {
      if (!isOriginAllowed(request, env)) return new Response(null, { status: 403, headers: cors });
      return new Response(null, { status: 204, headers: cors });
    }

    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return errorResponse(405, 'Method not allowed', cors);
    }

    if (!isOriginAllowed(request, env)) {
      return errorResponse(403, 'Origin not allowed', cors);
    }

    const requestUrl = new URL(request.url);
    const target = requestUrl.searchParams.get('url');
    if (!target) {
      return errorResponse(400, 'Missing url parameter', cors);
    }

    const checked = validateTarget(target);
    if (checked.error) {
      return errorResponse(400, checked.error, cors);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    let result;
    try {
      result = await fetchWithRedirects(checked.url, controller.signal);
    } catch (_) {
      clearTimeout(timer);
      return errorResponse(502, 'Failed to fetch the target', cors);
    }
    clearTimeout(timer);

    if (result.error) {
      return errorResponse(result.status || 502, result.error, cors);
    }

    const { response, finalUrl } = result;

    if (!response.ok) {
      return errorResponse(response.status === 404 ? 404 : 502, `Upstream responded with ${response.status}`, cors);
    }

    const contentType = response.headers.get('Content-Type') || '';
    if (!isAllowedContentType(contentType) && !hasAllowedExtension(finalUrl)) {
      return errorResponse(415, 'Only PDF and PPTX files are supported', cors);
    }

    const declaredLength = Number(response.headers.get('Content-Length') || 0);
    if (declaredLength > MAX_BYTES) {
      return errorResponse(413, 'File is too large', cors);
    }

    const headers = new Headers(cors);
    const outType = contentType && !contentType.toLowerCase().startsWith('text/')
      ? contentType
      : finalUrl.pathname.toLowerCase().endsWith('.pptx')
        ? 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
        : 'application/pdf';
    headers.set('Content-Type', outType);
    if (declaredLength > 0) headers.set('Content-Length', String(declaredLength));
    headers.set('Cache-Control', `public, max-age=${CACHE_TTL_SECONDS}`);
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('X-Final-Url', finalUrl.toString());

    if (request.method === 'HEAD' || !response.body) {
      return new Response(null, { status: 200, headers });
    }

    return new Response(limitStream(response.body, MAX_BYTES), { status: 200, headers });
  }
};
