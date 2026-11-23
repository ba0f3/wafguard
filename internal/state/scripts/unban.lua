-- Atomically clear all ban state and advance the fence, once per operation id.
-- KEYS[1]=operation, KEYS[2]=ban, KEYS[3]=contrib, KEYS[4]=suppression,
-- KEYS[5]=meta, KEYS[6]=fence, KEYS[7]=brute zset
-- ARGV[1]=operation id, ARGV[2]=generation, ARGV[3]=now_ms, ARGV[4]=suppression_ms,
-- ARGV[5]=fence ttl ms, ARGV[6]=app, ARGV[7]=ip
local prior = redis.call('HGET', KEYS[1], 'gen')
if prior then
  -- Exact retry: return the original result without touching current state
  -- (a newer ban must survive). A changed payload is a conflict.
  if redis.call('HGET', KEYS[1], 'app') == ARGV[6] and
     redis.call('HGET', KEYS[1], 'ip') == ARGV[7] and
     redis.call('HGET', KEYS[1], 'sup') == ARGV[4] then
    return {prior, redis.call('HGET', KEYS[1], 'exp')}
  end
  return {'conflict'}
end
local exp = string.format('%d', tonumber(ARGV[3]) + tonumber(ARGV[4]))
redis.call('DEL', KEYS[2], KEYS[3], KEYS[7])
if tonumber(ARGV[4]) > 0 then
  redis.call('SET', KEYS[4], exp, 'PX', tonumber(ARGV[4]))
else
  redis.call('DEL', KEYS[4])
end
redis.call('HSET', KEYS[5], 'generation', ARGV[2])
redis.call('PEXPIRE', KEYS[5], tonumber(ARGV[5]))
redis.call('SET', KEYS[6], ARGV[2], 'PX', tonumber(ARGV[5]))
redis.call('HSET', KEYS[1], 'gen', ARGV[2], 'app', ARGV[6], 'ip', ARGV[7],
           'sup', ARGV[4], 'exp', exp)
redis.call('PEXPIRE', KEYS[1], 604800000)
return {ARGV[2], exp}
