-- Atomic observe: dedupe by event id, verify the admission token, then update
-- bounded rolling windows. The auth hash is the single place where an auth
-- failure is joined to a WAF verdict, so a request is counted at most once.
-- KEYS[1]=dedupe, KEYS[2]=contrib zset, KEYS[3]=ban, KEYS[4]=meta, KEYS[5]=mode,
-- KEYS[6]=fence, KEYS[7]=auth hash, KEYS[8]=brute zset, KEYS[9]=admission token,
-- KEYS[10]=policy revision
-- ARGV: event_id, now_ms, waf_deny, waf_window_sec, waf_threshold, ban_ttl_sec,
-- default_mode, admission_gen, max_age_ms, admission_at_ms, brute_window_sec,
-- brute_threshold, request_id, app, client_ip, origin_status, final_status
if redis.call('EXISTS', KEYS[1]) == 1 then
  return {'deduped'}
end
local now = tonumber(ARGV[2])
local max_age = tonumber(ARGV[9])
local app, ip, rid = ARGV[14], ARGV[15], ARGV[13]
local token_gen = redis.call('HGET', KEYS[9], 'gen')
if not token_gen or redis.call('HGET', KEYS[9], 'app') ~= app or
   redis.call('HGET', KEYS[9], 'ip') ~= ip then
  return {'fenced', 'admission'}
end
local admitted_at = tonumber(redis.call('HGET', KEYS[9], 'at_ms'))
if (now - admitted_at) > max_age or admitted_at > now then
  return {'fenced', 'age'}
end
if ARGV[8] ~= '' and ARGV[8] ~= token_gen then
  return {'fenced', 'generation'}
end
local fence = redis.call('GET', KEYS[6])
if fence and fence ~= token_gen then
  return {'fenced', 'generation'}
end
redis.call('SET', KEYS[1], '1', 'PX', max_age)
redis.call('PEXPIRE', KEYS[4], max_age)
local mode = redis.call('GET', KEYS[5]) or ARGV[7]
local function brute_count()
  if redis.call('HGET', KEYS[7], 'outcome') ~= 'failure' then return nil end
  if redis.call('HSETNX', KEYS[7], 'brute_counted', '1') ~= 1 then return nil end
  redis.call('ZADD', KEYS[8], now, rid)
  local bwin = tonumber(ARGV[11])
  redis.call('ZREMRANGEBYSCORE', KEYS[8], 0, now - (bwin * 1000))
  redis.call('PEXPIRE', KEYS[8], bwin * 1000)
  local count = redis.call('ZCARD', KEYS[8])
  if count >= tonumber(ARGV[12]) and mode == 'enforce' then
    local ban_ttl = tonumber(ARGV[6])
    local exp = now + (ban_ttl * 1000)
    redis.call('SET', KEYS[3], exp, 'PX', ban_ttl * 1000)
    return {'brute_banned', count, exp}
  end
  return nil
end
if redis.call('EXISTS', KEYS[7]) == 1 then
  local outcome = redis.call('HGET', KEYS[7], 'outcome')
  if outcome and redis.call('HSETNX', KEYS[7], 'joined', '1') == 1 then
    redis.call('HSET', KEYS[7], 'joined_at_ms', ARGV[2])
    local br = brute_count()
    if br then return br end
  end
end
if ARGV[16] ~= '' then redis.call('HSET', KEYS[4], 'origin_status', ARGV[16], 'response_seen', '1') end
if ARGV[17] ~= '' then redis.call('HSET', KEYS[4], 'final_client_status', ARGV[17]) end
if tonumber(ARGV[3]) == 1 then
  redis.call('ZADD', KEYS[2], now, ARGV[1])
  local window = tonumber(ARGV[4])
  redis.call('ZREMRANGEBYSCORE', KEYS[2], 0, now - (window * 1000))
  redis.call('PEXPIRE', KEYS[2], window * 1000)
  local count = redis.call('ZCARD', KEYS[2])
  local threshold = tonumber(ARGV[5])
  if count >= threshold and mode == 'enforce' then
    local ban_ttl = tonumber(ARGV[6])
    local exp = now + (ban_ttl * 1000)
    redis.call('SET', KEYS[3], exp, 'PX', ban_ttl * 1000)
    return {'banned', count, exp}
  elseif count >= threshold then
    return {'shadow', count}
  end
end
return {'ok'}
