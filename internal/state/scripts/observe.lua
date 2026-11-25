-- Atomic observe: dedupe by event id, verify the admission token and current
-- policy revision, then update bounded rolling windows. Every counter change
-- is reported as a signal so the caller can log why an IP was flagged.
-- KEYS[1]=dedupe, KEYS[2]=contrib zset, KEYS[3]=ban, KEYS[4]=meta, KEYS[5]=mode,
-- KEYS[6]=fence, KEYS[7]=auth hash, KEYS[8]=brute zset, KEYS[9]=admission token,
-- KEYS[10]=policy revision, KEYS[11]=suppression, KEYS[12]=scanner zset,
-- KEYS[13]=ban history zset, KEYS[14]=ban info hash
-- ARGV: event_id, now_ms, waf_deny, waf_window_sec, waf_threshold, ban_ttl_sec,
-- default_mode, admission_gen, max_age_ms, admission_at_ms, brute_window_sec,
-- brute_threshold, request_id, app, client_ip, origin_status, final_status,
-- admission_rev, scanner_window_sec, scanner_responses, repeat_threshold,
-- repeat_window_sec, repeat_ttl_sec
local now = tonumber(ARGV[2])
local max_age = tonumber(ARGV[9])
local app, ip, rid = ARGV[14], ARGV[15], ARGV[13]
local ban_ttl = tonumber(ARGV[6])
local brute_window = tonumber(ARGV[11])
local brute_threshold = tonumber(ARGV[12])
local scanner_window = tonumber(ARGV[19])
local scanner_threshold = tonumber(ARGV[20])
local repeat_threshold = tonumber(ARGV[21])
local repeat_window = tonumber(ARGV[22])
local repeat_ttl = tonumber(ARGV[23])
local mode = ARGV[7]
local status = 'ok'
local ban_reason = ''
local ban_count, ban_threshold, ban_history, ban_ttl_used, ban_repeat = 0, 0, 0, 0, '0'
local signals = {}

local function finish()
  local out = {status, ban_reason, ban_count, ban_threshold, ban_history, ban_ttl_used, ban_repeat}
  for _, sig in ipairs(signals) do
    table.insert(out, sig)
  end
  return out
end
local function early(s)
  status = s
  return finish()
end
local function emit(reason, count, threshold)
  table.insert(signals, {reason, count, threshold})
end
-- rid is the zset member, so the same request counted by two different
-- signals cannot increase the same counter twice.
local function bump(key, window_sec, threshold, reason)
  redis.call('ZADD', key, now, rid)
  redis.call('ZREMRANGEBYSCORE', key, 0, now - (window_sec * 1000))
  redis.call('PEXPIRE', key, window_sec * 1000)
  local count = redis.call('ZCARD', key)
  emit(reason, count, threshold)
  return count
end
local function maybeBan(reason, count, threshold)
  if count < threshold or status == 'banned' then return end
  if mode == 'enforce' then
    -- A burst from one IP can cross the threshold on many replicas at once.
    -- Only the request that starts a new ban episode enters history; the rest
    -- are duplicate logs and must not inflate the repeat counter.
    local active = redis.call('GET', KEYS[3])
    if active and tonumber(active) and tonumber(active) > now then
      status = 'ban_active'
      ban_reason = reason
      return
    end
    redis.call('ZADD', KEYS[13], now, rid)
    redis.call('ZREMRANGEBYSCORE', KEYS[13], 0, now - (repeat_window * 1000))
    redis.call('PEXPIRE', KEYS[13], repeat_window * 1000)
    local history = redis.call('ZCARD', KEYS[13])
    local ttl = ban_ttl
    if history >= repeat_threshold then ttl = repeat_ttl end
    redis.call('SET', KEYS[3], now + (ttl * 1000), 'PX', ttl * 1000)
    redis.call('HSET', KEYS[14], 'reason', reason, 'count', history,
               'threshold', repeat_threshold, 'at_ms', ARGV[2])
    redis.call('PEXPIRE', KEYS[14], ttl * 1000)
    status = 'banned'
    ban_reason, ban_count, ban_threshold = reason, count, threshold
    ban_history, ban_ttl_used = history, ttl
    ban_repeat = (history >= repeat_threshold) and '1' or '0'
  else
    status = 'shadow'
    ban_reason, ban_count, ban_threshold = reason, count, threshold
  end
end

if redis.call('EXISTS', KEYS[1]) == 1 then
  return early('deduped')
end
local token_gen = redis.call('HGET', KEYS[9], 'gen')
if not token_gen or redis.call('HGET', KEYS[9], 'app') ~= app or
   redis.call('HGET', KEYS[9], 'ip') ~= ip then
  return early('fenced')
end
local admitted_at = tonumber(redis.call('HGET', KEYS[9], 'at_ms'))
if (now - admitted_at) > max_age or admitted_at > now then
  return early('fenced')
end
local token_rev = redis.call('HGET', KEYS[9], 'rev') or '0'
if ARGV[18] ~= '' and ARGV[18] ~= token_rev then
  return early('fenced')
end
if (redis.call('GET', KEYS[10]) or '0') ~= token_rev then
  return early('fenced')
end
if ARGV[8] ~= '' and ARGV[8] ~= token_gen then
  return early('fenced')
end
local fence = redis.call('GET', KEYS[6])
if fence and fence ~= token_gen then
  return early('fenced')
end
redis.call('SET', KEYS[1], '1', 'PX', max_age)
local sup = redis.call('GET', KEYS[11])
if sup and tonumber(sup) > now then
  return early('suppressed')
end
mode = redis.call('GET', KEYS[5]) or ARGV[7]

-- Auth failures are joined to the admission token; keep the joined marker for
-- the existing receipt-order tests and count the failure only once.
if redis.call('EXISTS', KEYS[7]) == 1 then
  local outcome = redis.call('HGET', KEYS[7], 'outcome')
  if outcome and redis.call('HSETNX', KEYS[7], 'joined', '1') == 1 then
    redis.call('HSET', KEYS[7], 'joined_at_ms', ARGV[2])
    if outcome == 'failure' and redis.call('HSETNX', KEYS[7], 'brute_counted', '1') == 1 then
      local count = bump(KEYS[8], brute_window, brute_threshold, 'brute_auth')
      maybeBan('brute_auth', count, brute_threshold)
    end
  end
end

-- Status observation is opt-in; only create (and then bound) the meta hash
-- when a status actually arrives.
if ARGV[16] ~= '' then
  redis.call('HSET', KEYS[4], 'origin_status', ARGV[16], 'response_seen', '1')
  redis.call('PEXPIRE', KEYS[4], max_age)
end
if ARGV[17] ~= '' then
  redis.call('HSET', KEYS[4], 'final_client_status', ARGV[17])
  redis.call('PEXPIRE', KEYS[4], max_age)
end

local origin = tonumber(ARGV[16] or '')
if origin then
  if origin == 401 then
    local count = bump(KEYS[8], brute_window, brute_threshold, 'brute_401')
    maybeBan('brute_401', count, brute_threshold)
  elseif origin == 404 then
    local count = bump(KEYS[12], scanner_window, scanner_threshold, 'scanner_404')
    maybeBan('scanner_404', count, scanner_threshold)
  elseif origin >= 500 and origin <= 504 then
    emit('backend_5xx', origin, 0)
  end
end

if tonumber(ARGV[3]) == 1 then
  local count = bump(KEYS[2], tonumber(ARGV[4]), tonumber(ARGV[5]), 'waf_deny')
  maybeBan('waf_deny', count, tonumber(ARGV[5]))
end

return finish()
