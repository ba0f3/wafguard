-- Join an auth outcome to the real admission token for the request.
-- KEYS[1]=auth hash, KEYS[2]=waf-verdict dedupe, KEYS[3]=brute zset,
-- KEYS[4]=ban, KEYS[5]=mode, KEYS[6]=admission token, KEYS[7]=fence, KEYS[8]=meta,
-- KEYS[9]=suppression, KEYS[10]=policy revision
-- ARGV: outcome, source_id, now_ms, brute_window_sec, brute_threshold,
-- ban_ttl_sec, request_id, default_mode, expected_source, app, max_age_ms, ttl_sec,
-- expected_ip, expected_rev
if redis.call('HGET', KEYS[1], 'outcome') then
  return {'duplicate'}
end
local token_gen = redis.call('HGET', KEYS[6], 'gen')
local token_ip = redis.call('HGET', KEYS[6], 'ip')
local token_rev = redis.call('HGET', KEYS[6], 'rev') or '0'
if not token_gen or redis.call('HGET', KEYS[6], 'app') ~= ARGV[10] or
   redis.call('HGET', KEYS[6], 'rid') ~= ARGV[7] then
  return {'unjoined'}
end
-- Keys were computed by the caller from a token read before this script ran.
-- Reject if the token changed in between, or if the policy revision moved.
if token_ip ~= ARGV[13] or token_rev ~= ARGV[14] then
  return {'fenced', 'token_changed'}
end
if (redis.call('GET', KEYS[10]) or '0') ~= token_rev then
  return {'fenced', 'revision'}
end
if ARGV[2] ~= ARGV[9] then
  return {'source_mismatch'}
end
local now = tonumber(ARGV[3])
local admitted_at = tonumber(redis.call('HGET', KEYS[6], 'at_ms'))
if admitted_at > now or (now - admitted_at) > tonumber(ARGV[11]) then
  return {'fenced', 'age'}
end
local fence = redis.call('GET', KEYS[7])
if fence and fence ~= token_gen then
  return {'fenced', 'generation'}
end
-- Everything below is derived from the admission, never from the caller.
local token_at = redis.call('HGET', KEYS[6], 'at_ms')
redis.call('HSET', KEYS[1], 'outcome', ARGV[1], 'source', ARGV[2],
           'client_ip', token_ip, 'generation', token_gen, 'admission_at_ms', token_at,
           'request_id', ARGV[7], 'app', ARGV[10])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[12]))
if redis.call('EXISTS', KEYS[2]) == 1 and redis.call('HSETNX', KEYS[1], 'joined', '1') == 1 then
  redis.call('HSET', KEYS[1], 'joined_at_ms', ARGV[3])
end
local sup = redis.call('GET', KEYS[9])
if sup and tonumber(sup) > now then
  return {'suppressed'}
end
if ARGV[1] == 'failure' and redis.call('HSETNX', KEYS[1], 'brute_counted', '1') == 1 then
  redis.call('ZADD', KEYS[3], now, ARGV[7])
  local bwin = tonumber(ARGV[4])
  redis.call('ZREMRANGEBYSCORE', KEYS[3], 0, now - (bwin * 1000))
  redis.call('PEXPIRE', KEYS[3], bwin * 1000)
  local count = redis.call('ZCARD', KEYS[3])
  local mode = redis.call('GET', KEYS[5]) or ARGV[8]
  if count >= tonumber(ARGV[5]) and mode == 'enforce' then
    local ban_ttl = tonumber(ARGV[6])
    local exp = now + (ban_ttl * 1000)
    redis.call('SET', KEYS[4], exp, 'PX', ban_ttl * 1000)
    return {'brute_banned', count, exp}
  end
end
return {'ok'}
