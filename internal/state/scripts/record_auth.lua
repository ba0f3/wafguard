-- KEYS[1]=auth hash, KEYS[2]=waf-verdict dedupe for same request
-- ARGV: outcome, source_id, now_ms
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
return {'ok'}
