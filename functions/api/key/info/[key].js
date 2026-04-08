export async function onRequestGet(context) {
  const { request, env } = context
  const url = new URL(request.url)
  const key = url.pathname.split('/').pop()
  if (!key) {
    return new Response(JSON.stringify({ error: 'Key required' }), { status: 400, headers: { 'Content-Type': 'application/json' } })
  }

  const data = await env.KEYS.get(key, 'json')
  const now = Math.floor(Date.now() / 1000)
  if (!data) {
    return new Response(JSON.stringify({ error: 'Key not found' }), { status: 404, headers: { 'Content-Type': 'application/json' } })
  }
  const valid = data.active && data.expires_at > now
  return new Response(JSON.stringify({
    key,
    created_at: data.created_at,
    expires_at: data.expires_at,
    active: data.active,
    valid
  }), { headers: { 'Content-Type': 'application/json' } })
}