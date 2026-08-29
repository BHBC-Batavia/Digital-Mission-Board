export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = url.origin; // this Worker's own URL, used as the OAuth redirect target

    if (url.pathname === '/auth') {
      const state = crypto.randomUUID();
      const authorizeUrl = new URL('https://github.com/login/oauth/authorize');
      authorizeUrl.searchParams.set('client_id', env.CLIENT_ID);
      authorizeUrl.searchParams.set('redirect_uri', `${origin}/callback`);
      authorizeUrl.searchParams.set('scope', 'repo,user');
      authorizeUrl.searchParams.set('state', state);
      return Response.redirect(authorizeUrl.toString(), 302);
    }

    if (url.pathname === '/callback') {
      const code = url.searchParams.get('code');
      if (!code) {
        return new Response('Missing code from GitHub', { status: 400 });
      }

      const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({
          client_id: env.CLIENT_ID,
          client_secret: env.CLIENT_SECRET,
          code
        })
      });

      const tokenData = await tokenRes.json();

      if (tokenData.error || !tokenData.access_token) {
        return new Response(
          'GitHub token exchange failed: ' + (tokenData.error_description || JSON.stringify(tokenData)),
          { status: 400 }
        );
      }

      // Standard Decap CMS popup handshake: post a message back to the admin page opener.
      const tokenJson = JSON.stringify({ token: tokenData.access_token, provider: 'github' });
      const html = `<!DOCTYPE html><html><body>
<script>
(function() {
  var payload = ${tokenJson};
  function receiveMessage(e) {
    window.opener.postMessage('authorization:github:success:' + JSON.stringify(payload), e.origin);
    window.removeEventListener('message', receiveMessage, false);
  }
  window.addEventListener('message', receiveMessage, false);
  window.opener.postMessage('authorizing:github', '*');
})();
</script>
</body></html>`;

      return new Response(html, { headers: { 'Content-Type': 'text/html' } });
    }

    return new Response('Decap CMS OAuth relay is running. Use /auth to start login.', { status: 200 });
  }
};
