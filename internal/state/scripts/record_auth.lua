-- KEYS[1]=auth hash, KEYS[2]=waf-verdict dedupe, KEYS[3]=brute zset, KEYS[4]=ban, KEYS[5]=mode
-- ARGV: outcome, source_id, now_ms, brute_window_sec, brute_threshold, ban_ttl_sec, request_id, default_mode
if redis.call('HGET', KEYS[1], 'outcome') then
  return {'duplicate'}
end
redis.call('HSET', KEYS[1], 'outcome', ARGV[1], 'source', ARGV[2])
redis.call('EXPIRE', KEYS[1], 86400)
if redis.call('EXISTS', KEYS[2]) == 1 then
  if redis.call('HSETNX', KEYS[1], 'joined', '1') == 1 then
    redis.call('HSET', KEYS[1], 'joined_at_ms', ARGV[3])
  end
end
if ARGV[1] == 'failure' and redis.call('HSETNX', KEYS[1], 'brute_counted', '1') == 1 then
  local now = tonumber(ARGV[3])
  redis.call('ZADD', KEYS[3], now, ARGV[7])
  local bwin = tonumber(ARGV[4])
  redis.call('ZREMRANGEBYSCORE', KEYS[3], 0, now - (bwin * 1000))
  local bcount = redis.call('ZCARD', KEYS[3])
  local bthresh = tonumber(ARGV[5])
  local mode = redis.call('GET', KEYS[5]) or ARGV[8]
  if bcount >= bthresh and mode == 'enforce' then
    local ban_ttl = tonumber(ARGV[6])
    local exp = now + (ban_ttl * 1000)
    redis.call('SET', KEYS[4], exp, 'PX', ban_ttl * 1000)
    return {'brute_banned', bcount, exp}
  end
end
return {'ok'}
