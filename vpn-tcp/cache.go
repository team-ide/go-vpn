package vpn_tcp

import (
	"github.com/patrickmn/go-cache"
	"time"
)

// 超时缓存 默认30分钟超时 10分钟检测一次
var timeCache = cache.New(30*time.Minute, 10*time.Minute)
