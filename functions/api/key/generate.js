export async function onRequestPost(context) {
  const { request, env } = context
  const BOT_SECRET = env.BOT_SECRET || 'change_this_secret'
  const authHeader = request.headers.get('Authorization')
  if (!authHeader || authHeader !== `Bearer ${BOT_SECRET}`) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } })
  }

  const key = crypto.randomUUID().replace(/-/g, '')
  const now = Math.floor(Date.now() / 1000)
  const expiresAt = now + 86400

  await env.KEYS.put(key, JSON.stringify({
    created_at: now,
    expires_at: expiresAt,
    active: 1
  }), { expirationTtl: 86400 })

  return new Response(JSON.stringify({ key, expires_at: expiresAt }), { headers: { 'Content-Type': 'application/json' } })
}