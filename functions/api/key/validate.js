export async function onRequestPost(context) {
  const { request, env } = context
  const { key } = await request.json()
  if (!key) {
    return new Response(JSON.stringify({ error: 'Key required' }), { status: 400, headers: { 'Content-Type': 'application/json' } })
  }

  const data = await env.KEYS.get(key, 'json')
  const now = Math.floor(Date.now() / 1000)

  if (!data) {
    return new Response(JSON.stringify({ valid: false, reason: 'invalid_key' }), { headers: { 'Content-Type': 'application/json' } })
  }
  if (!data.active) {
    return new Response(JSON.stringify({ valid: false, reason: 'inactive' }), { headers: { 'Content-Type': 'application/json' } })
  }
  if (data.expires_at < now) {
    return new Response(JSON.stringify({ valid: false, reason: 'expired', expires_at: data.expires_at }), { headers: { 'Content-Type': 'application/json' } })
  }
  return new Response(JSON.stringify({ valid: true, expires_at: data.expires_at }), { headers: { 'Content-Type': 'application/json' } })
}