package utils

// import (
// 	"sync"
// 	"time"
// )

// type cacheItem struct {
// 	value      interface{}
// 	expiration time.Time
// }

// type Cache struct {
// 	items map[string]cacheItem
// 	mu    sync.RWMutex
// }

// func NewCache(defaultExpiration time.Duration) *Cache {
// 	cache := &Cache{
// 		items: make(map[string]cacheItem),
// 	}

// 	// Start cleanup goroutine
// 	go cache.cleanup(defaultExpiration)

// 	return cache
// }

// func (c *Cache) Set(key string, value interface{}, expiration time.Duration) {
// 	c.mu.Lock()
// 	defer c.mu.Unlock()

// 	c.items[key] = cacheItem{
// 		value:      value,
// 		expiration: time.Now().Add(expiration),
// 	}
// }

// func (c *Cache) Get(key string) (interface{}, bool) {
// 	c.mu.RLock()
// 	defer c.mu.RUnlock()

// 	item, exists := c.items[key]
// 	if !exists {
// 		return nil, false
// 	}

// 	if time.Now().After(item.expiration) {
// 		return nil, false
// 	}

// 	return item.value, true
// }

// func (c *Cache) Increment(key string, expiration time.Duration) (int, error) {
// 	c.mu.Lock()
// 	defer c.mu.Unlock()

// 	item, exists := c.items[key]
// 	var count int

// 	if exists {
// 		count = item.value.(int) + 1
// 	} else {
// 		count = 1
// 	}

// 	c.items[key] = cacheItem{
// 		value:      count,
// 		expiration: time.Now().Add(expiration),
// 	}

// 	return count, nil
// }

// func (c *Cache) cleanup(interval time.Duration) {
// 	ticker := time.NewTicker(interval)
// 	defer ticker.Stop()

// 	for range ticker.C {
// 		c.mu.Lock()
// 		now := time.Now()

// 		for key, item := range c.items {
// 			if now.After(item.expiration) {
// 				delete(c.items, key)
// 			}
// 		}

// 		c.mu.Unlock()
// 	}
// }
