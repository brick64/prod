import redis
import os

REDIS_URL = os.getenv("REDIS_URL", "redis://my_redis:6379/0")

redis_session = redis.from_url(REDIS_URL)
# redis_session = redis.Redis()
