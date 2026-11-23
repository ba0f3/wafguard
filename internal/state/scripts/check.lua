-- KEYS[1]=ban, KEYS[2]=meta, KEYS[3]=mode, KEYS[4]=suppression, KEYS[5]=fence,
-- KEYS[6]=policy revision, KEYS[7]=admission token, KEYS[8]=policy config
-- ARGV[1]=now_ms, ARGV[2]=default_mode, ARGV[3]=request_id, ARGV[4]=admission_ttl_ms,
-- ARGV[5]=client_ip, ARGV[6]=app
-- The admission token is what later phases must present. It is bound to this
-- IP, generation and timestamp at admission time, never at observation time.
local now = tonumber(ARGV[1])
local ttl = tonumber(ARGV[4])
local function remember(gen, rev, mode)
  if ARGV[3] == '' then return end
  redis.call('HSET', KEYS[7], 'gen', gen, 'rev', tostring(rev), 'mode', mode,
             'ip', ARGV[5], 'app', ARGV[6], 'at_ms', ARGV[1], 'rid', ARGV[3])
  redis.call('PEXPIRE', KEYS[7], ttl)
end
local function generation()
  local gen = redis.call('GET', KEYS[5])
  if not gen then gen = redis.call('HGET', KEYS[2], 'generation') end
  if not gen then
    gen = redis.sha1hex(redis.call('TIME')[1] .. KEYS[2])
    redis.call('HSET', KEYS[2], 'generation', gen)
    redis.call('PEXPIRE', KEYS[2], ttl)
  end
  return gen
end
local function revision()
  return redis.call('GET', KEYS[6]) or redis.call('HGET', KEYS[2], 'revision') or '0'
end
local ban = redis.call('GET', KEYS[1])
if ban then
  local exp = tonumber(ban)
  if exp > now then
    local gen, rev = generation(), revision()
    remember(gen, rev, redis.call('GET', KEYS[3]) or ARGV[2])
    return {'ban', ban, gen, rev, redis.call('GET', KEYS[3]) or ARGV[2]}
  end
  redis.call('DEL', KEYS[1])
end
local sup = redis.call('GET', KEYS[4])
if sup and tonumber(sup) > now then
  local gen, rev = generation(), revision()
  remember(gen, rev, redis.call('GET', KEYS[3]) or ARGV[2])
  return {'allow', '0', gen, rev, redis.call('GET', KEYS[3]) or ARGV[2], 'suppressed'}
end
local gen, rev = generation(), revision()
local mode = redis.call('GET', KEYS[3]) or ARGV[2]
remember(gen, rev, mode)
return {'allow', '0', gen, rev, mode}
