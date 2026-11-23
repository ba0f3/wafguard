-- Atomic observe: dedupe by event id, update rolling windows, maybe ban.
-- KEYS[1]=dedupe, KEYS[2]=contrib zset, KEYS[3]=ban, KEYS[4]=meta, KEYS[5]=mode, KEYS[6]=fence gen
-- ARGV: event_id, now_ms, waf_deny (0/1), window_sec, ban_ttl_sec, threshold, mode, admission_gen, max_event_age_ms, admission_at_ms
if redis.call('EXISTS', KEYS[1]) == 1 then
  return {'deduped'}
end
local now = tonumber(ARGV[2])
local admission_at = tonumber(ARGV[10])
local max_age = tonumber(ARGV[9])
if admission_at > 0 and (now - admission_at) > max_age then
  return {'fenced', 'age'}
end
local fence = redis.call('GET', KEYS[6])
if fence and ARGV[8] ~= '' and fence ~= ARGV[8] then
  return {'fenced', 'generation'}
end
redis.call('SET', KEYS[1], '1', 'EX', max_age)
local waf_deny = tonumber(ARGV[3])
if waf_deny == 1 then
  redis.call('ZADD', KEYS[2], now, ARGV[1])
  local window = tonumber(ARGV[4])
  redis.call('ZREMRANGEBYSCORE', KEYS[2], 0, now - (window * 1000))
  local count = redis.call('ZCARD', KEYS[2])
  local threshold = tonumber(ARGV[5])
  local mode = redis.call('GET', KEYS[5]) or ARGV[7]
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

