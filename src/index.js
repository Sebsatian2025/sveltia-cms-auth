// src/index.js

/**
 * List of supported OAuth providers.
 */
const supportedProviders = ['github', 'gitlab'];

/**
 * Escape the given string for safe use in a regular expression.
 */
const escapeRegExp = (str) =>
  str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * Output HTML response that communicates with the window opener.
 */
const outputHTML = ({ provider = 'unknown', token, error, errorCode }) => {
  const state = error ? 'error' : 'success';
  const content = error
    ? { provider, error, errorCode }
    : { provider, token };

  return new Response(
    `<!doctype html>
<html><body><script>
  (() => {
    window.addEventListener('message', ({ data, origin }) => {
      if (data === 'authorizing:${provider}') {
        window.opener?.postMessage(
          'authorization:${provider}:${state}:${JSON.stringify(content)}',
          origin
        );
      }
    });
    window.opener?.postMessage('authorizing:${provider}', '*');
  })();
</script></body></html>`,
    {
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        // Borramos el CSRF token con SameSite=None
        'Set-Cookie': `csrf-token=deleted; HttpOnly; Max-Age=0; Path=/; SameSite=None; Secure`
      }
    }
  );
};

/**
 * Handle the `auth` method: initiate OAuth flow.
 */
const handleAuth = async (request, env) => {
  const { searchParams } = new URL(request.url);
  const { provider, site_id: domain } = Object.fromEntries(searchParams);

  if (!supportedProviders.includes(provider)) {
    return outputHTML({
      error: 'Your Git backend is not supported by the authenticator.',
      errorCode: 'UNSUPPORTED_BACKEND'
    });
  }

  const {
    ALLOWED_DOMAINS,
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_HOSTNAME = 'github.com',
    GITLAB_CLIENT_ID,
    GITLAB_CLIENT_SECRET,
    GITLAB_HOSTNAME = 'gitlab.com'
  } = env;

  // Domain whitelist
  if (
    ALLOWED_DOMAINS &&
    !ALLOWED_DOMAINS.split(',').some((str) =>
      (domain ?? '').match(
        new RegExp(`^${escapeRegExp(str.trim()).replace('\\*', '.+')}$`)
      )
    )
  ) {
    return outputHTML({
      provider,
      error: 'Your domain is not allowed to use the authenticator.',
      errorCode: 'UNSUPPORTED_DOMAIN'
    });
  }

  // CSRF token
  const csrfToken = crypto.randomUUID().replaceAll('-', '');
  let authURL = '';

  // GitHub auth URL
  if (provider === 'github') {
    if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET) {
      return outputHTML({
        provider,
        error: 'OAuth app client ID or secret is not configured.',
        errorCode: 'MISCONFIGURED_CLIENT'
      });
    }
    const params = new URLSearchParams({
      client_id: GITHUB_CLIENT_ID,
      scope: 'repo,read:user,user:email',
      state: csrfToken
    });
    authURL = `https://${GITHUB_HOSTNAME}/login/oauth/authorize?${params}`;
  }

  // GitLab auth URL
  if (provider === 'gitlab') {
    if (!GITLAB_CLIENT_ID || !GITLAB_CLIENT_SECRET) {
      return outputHTML({
        provider,
        error: 'OAuth app client ID or secret is not configured.',
        errorCode: 'MISCONFIGURED_CLIENT'
      });
    }
    const params = new URLSearchParams({
      client_id: GITLAB_CLIENT_ID,
      redirect_uri: `${new URL(request.url).origin}/callback`,
      response_type: 'code',
      scope: 'api',
      state: csrfToken
    });
    authURL = `https://${GITLAB_HOSTNAME}/oauth/authorize?${params}`;
  }

  // Redirigir a GitHub/GitLab y setear CSRF cookie como first-party
  return new Response('', {
    status: 302,
    headers: {
      Location: authURL,
      'Set-Cookie': `csrf-token=${provider}_${csrfToken}; HttpOnly; Path=/; Max-Age=600; SameSite=None; Secure`
    }
  });
};

/**
 * Handle the `callback` method: complete OAuth flow.
 */
const handleCallback = async (request) => {
  const { searchParams, origin } = new URL(request.url);
  const { code, state } = Object.fromEntries(searchParams);
  const cookie = request.headers.get('Cookie') || '';
  const [, provider, csrfToken] =
    cookie.match(/\bcsrf-token=([a-z-]+?)_([0-9a-f]{32})\b/) ?? [];

  if (!supportedProviders.includes(provider)) {
    return outputHTML({
      error: 'Your Git backend is not supported by the authenticator.',
      errorCode: 'UNSUPPORTED_BACKEND'
    });
  }
  if (!code || !state) {
    return outputHTML({
      provider,
      error: 'Failed to receive an authorization code.',
      errorCode: 'AUTH_CODE_REQUEST_FAILED'
    });
  }
  if (state !== csrfToken) {
    return outputHTML({
      provider,
      error: 'Potential CSRF attack detected.',
      errorCode: 'CSRF_DETECTED'
    });
  }

  const {
    GITHUB_CLIENT_ID,
    GITHUB_CLIENT_SECRET,
    GITHUB_HOSTNAME = 'github.com',
    GITLAB_CLIENT_ID,
    GITLAB_CLIENT_SECRET,
    GITLAB_HOSTNAME = 'gitlab.com'
  } = env;

  let tokenURL, requestBody;
  if (provider === 'github') {
    tokenURL = `https://${GITHUB_HOSTNAME}/login/oauth/access_token`;
    requestBody = { code, client_id: GITHUB_CLIENT_ID, client_secret: GITHUB_CLIENT_SECRET };
  } else {
    tokenURL = `https://${GITLAB_HOSTNAME}/oauth/token`;
    requestBody = {
      code,
      client_id: GITLAB_CLIENT_ID,
      client_secret: GITLAB_CLIENT_SECRET,
      grant_type: 'authorization_code',
      redirect_uri: `${origin}/callback`
    };
  }

  let res, json;
  try {
    res = await fetch(tokenURL, {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody)
    });
    json = await res.json();
  } catch {
    return outputHTML({
      provider,
      error: 'Failed to request an access token.',
      errorCode: 'TOKEN_REQUEST_FAILED'
    });
  }

  return outputHTML({ provider, token: json.access_token, error: json.error });
};

/**
 * Main fetch handler: primero OAuth, luego static site.
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;

    // 1) OAuth endpoints
    if (
      request.method === 'GET' &&
      ['/auth', '/oauth/authorize'].includes(pathname)
    ) {
      return handleAuth(request, env);
    }
    if (
      request.method === 'GET' &&
      ['/callback', '/oauth/redirect'].includes(pathname)
    ) {
      return handleCallback(request, env);
    }

    // 2) Redirige "/admin" → "/admin/"
    if (request.method === 'GET' && pathname === '/admin') {
      return Response.redirect(`${url.origin}/admin/`, 302);
    }

    // 3) Static assets (Workers Sites: public/)
    if (request.method === 'GET') {
      return env.__STATIC_CONTENT.fetch(request);
    }

    // 4) Fallback 404
    return new Response('Not found', { status: 404 });
  }
};
