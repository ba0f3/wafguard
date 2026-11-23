-- Compare-and-set policy revision, config, mode and fence in one atomic step.
-- KEYS[1]=revision, KEYS[2]=config json, KEYS[3]=mode, KEYS[4]=fence
-- ARGV[1]=expected_revision, ARGV[2]=config json, ARGV[3]=mode,
-- ARGV[4]=fence generation, ARGV[5]=fence ttl ms
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local expected = tonumber(ARGV[1])
if current ~= expected then
  return {'stale', tostring(current)}
end
local next = current + 1
redis.call('SET', KEYS[2], ARGV[2])
redis.call('SET', KEYS[3], ARGV[3])
redis.call('SET', KEYS[4], ARGV[4], 'PX', tonumber(ARGV[5]))
redis.call('SET', KEYS[1], tostring(next))
return {'ok', tostring(next)}
