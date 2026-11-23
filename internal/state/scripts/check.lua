-- KEYS[1]=ban, KEYS[2]=meta, KEYS[3]=mode, KEYS[4]=suppression, KEYS[5]=fence
-- ARGV[1]=now_ms, ARGV[2]=default_mode
local now = tonumber(ARGV[1])
local ban = redis.call('GET', KEYS[1])
if ban then
  local exp = tonumber(ban)
  if exp > now then
    return {'ban', exp, redis.call('HGET', KEYS[2], 'generation') or '', redis.call('HGET', KEYS[2], 'revision') or '0', redis.call('GET', KEYS[3]) or ARGV[2]}
  end
  redis.call('DEL', KEYS[1])
end
local sup = redis.call('GET', KEYS[4])
if sup and tonumber(sup) > now then
  return {'allow', '0', redis.call('HGET', KEYS[2], 'generation') or '', redis.call('HGET', KEYS[2], 'revision') or '0', redis.call('GET', KEYS[3]) or ARGV[2], 'suppressed'}
end
local fence = redis.call('GET', KEYS[5])
local gen = fence
if not gen then
  gen = redis.call('HGET', KEYS[2], 'generation')
end
if not gen then
  gen = redis.sha1hex(redis.call('TIME')[1] .. KEYS[2])
  redis.call('HSET', KEYS[2], 'generation', gen)
end
local rev = redis.call('HGET', KEYS[2], 'revision') or '0'
local mode = redis.call('GET', KEYS[3]) or ARGV[2]
return {'allow', '0', gen, rev, mode}

