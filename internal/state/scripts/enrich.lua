-- KEYS[1] dedupe/enrich record
-- ARGV: rule_id, tags, severity, phase, ttl_sec
if redis.call('EXISTS', KEYS[1]) == 1 then
  return {'deduped'}
end
redis.call('HSET', KEYS[1], 'rule_id', ARGV[1], 'tags', ARGV[2], 'severity', ARGV[3], 'phase', ARGV[4])
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[5]))
return {'ok'}
