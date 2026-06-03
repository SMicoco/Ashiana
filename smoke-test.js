/* Smoke test: confirms the backend works end-to-end.
   Usage:
     1. Open another terminal, run:  node server.js
     2. In this terminal:             node smoke-test.js
*/
const URL = process.env.BACKEND_URL || 'http://localhost:3000';

async function call(method, path, body, cookie) {
  const headers = { 'Content-Type': 'application/json' };
  if (cookie) headers['Cookie'] = cookie;
  const r = await fetch(URL + path, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const ct = r.headers.get('content-type') || '';
  const data = ct.includes('json') ? await r.json() : await r.text();
  const setCookie = r.headers.get('set-cookie') || '';
  return { status: r.status, data, setCookie };
}

(async () => {
  console.log('-> Backend URL:', URL);

  console.log('\n[1] Health check');
  console.log('   ', await call('GET', '/api/health'));

  console.log('\n[2] Submit a fake compliment');
  console.log('   ', await call('POST', '/api/submit', {
    form_type: 'compliment',
    name: 'Smoke Test',
    email: 'test@example.com',
    telephone: '0114 000 0000',
    position: 'Tester',
    message: 'This is a test submission. Delete me.',
  }));

  console.log('\n[3] Login with default admin credentials');
  const login = await call('POST', '/api/admin/login', {
    username: process.env.ADMIN_USERNAME || 'admin',
    password: process.env.ADMIN_PASSWORD || 'changeme123',
  });
  console.log('   ', login);
  const cookieMatch = (login.setCookie || '').match(/ashiana_admin=[^;]+/);
  const cookie = cookieMatch ? cookieMatch[0] : '';

  if (!cookie) { console.error('Login did not return a session cookie. Stopping.'); process.exit(1); }

  console.log('\n[4] Whoami');
  console.log('   ', await call('GET', '/api/admin/me', null, cookie));

  console.log('\n[5] Counts');
  console.log('   ', await call('GET', '/api/admin/counts', null, cookie));

  console.log('\n[6] List compliments');
  console.log('   ', await call('GET', '/api/admin/submissions?form_type=compliment&page=1&pageSize=10', null, cookie));

  console.log('\nAll checks passed. Backend is healthy.');
})();
