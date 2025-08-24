export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/auth') {
      return new Response('✅ AUTH OK', {
        status: 200,
        headers: { 'Content-Type': 'text/plain' }
      });
    }
    return new Response('❌ NOT FOUND', { status: 404 });
  }
};
