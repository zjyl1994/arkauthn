package utils

import (
	"time"

	"github.com/coocood/freecache"
)

type freeCacheStorage struct {
	cache *freecache.Cache
}

func NewFreeCacheStorage(capacity int) *freeCacheStorage {
	return &freeCacheStorage{
		cache: freecache.NewCache(capacity),
	}
}

func (f *freeCacheStorage) Get(key string) string {
	value, err := f.cache.Get([]byte(key))
	if err != nil {
		return ""
	}
	return string(value)
}

func (f *freeCacheStorage) Set(key, data string, expire time.Time) {
	var ttl int
	if expire.IsZero() {
		ttl = 0
	} else {
		ttl = int(time.Until(expire).Seconds())
		if ttl < 1 {
			ttl = 1
		}
	}
	f.cache.Set([]byte(key), []byte(data), ttl)
}

func (f *freeCacheStorage) Del(key string) {
	f.cache.Del([]byte(key))
}
