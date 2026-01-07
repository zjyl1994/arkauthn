package utils

import (
	"sync"
	"time"
)

// ErrorSlidingWindowLimiter 实现了一个基于滑动窗口的错误尝试限流器。
type ErrorSlidingWindowLimiter struct {
	maxErrors int           // 允许的最大错误次数
	window    time.Duration // 窗口大小（秒）
	errors    sync.Map      // 记录的错误时间戳列表
	mu        sync.Mutex    // 互斥锁，保证并发安全
}

// NewErrorSlidingWindowLimiter 创建一个新的错误尝试限流器实例。
func NewErrorSlidingWindowLimiter(maxErrors int, window time.Duration) *ErrorSlidingWindowLimiter {
	return &ErrorSlidingWindowLimiter{
		maxErrors: maxErrors,
		window:    window,
	}
}

// IsLimited 检查是否被限流。
func (l *ErrorSlidingWindowLimiter) IsLimited(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	errorList, ok := l.errors.Load(ip)
	if ok {
		errors := errorList.([]time.Time)
		// 清除过期的错误记录
		cutoff := now.Add(-l.window)
		// 找到第一个未过期的记录索引
		firstValid := 0
		for firstValid < len(errors) && errors[firstValid].Before(cutoff) {
			firstValid++
		}
		
		// 如果有过期记录，切片并更新回Map
		if firstValid > 0 {
			errors = errors[firstValid:]
			l.errors.Store(ip, errors)
		}

		// 如果当前窗口内的错误数量达到最大值，则返回true表示被限流
		return len(errors) >= l.maxErrors
	}
	
	return false
}

// RecordError 记录一次错误。
func (l *ErrorSlidingWindowLimiter) RecordError(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	errorList, ok := l.errors.Load(ip)
	if ok {
		errors := errorList.([]time.Time)
		errors = append(errors, time.Now())
		l.errors.Store(ip, errors)
	} else {
		l.errors.Store(ip, []time.Time{time.Now()})
	}
}
