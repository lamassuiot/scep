package scepserver

import (
	"context"
	"fmt"
	"time"

	"github.com/go-kit/kit/metrics"
)

type instrumentingMiddleware struct {
	requestCount   metrics.Counter
	requestLatency metrics.Histogram
	next           Service
}

func NewInstrumentingMiddleware(counter metrics.Counter, latency metrics.Histogram, next Service) Service {
	return &instrumentingMiddleware{
		requestCount:   counter,
		requestLatency: latency,
		next:           next,
	}
}

func (mw *instrumentingMiddleware) Health(ctx context.Context) bool {
	defer func(begin time.Time) {
		lvs := []string{"method", "Health", "error", "false"}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.Health(ctx)
}

func (mw *instrumentingMiddleware) GetCACaps(ctx context.Context) (caps []byte, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetCACaps", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetCACaps(ctx)
}

func (mw *instrumentingMiddleware) GetCACert(ctx context.Context) (cert []byte, certNum int, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetCACert", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetCACert(ctx)
}

func (mw *instrumentingMiddleware) PKIOperation(ctx context.Context, data []byte) (certRep []byte, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "PKIOperation", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.PKIOperation(ctx, data)
}

func (mw *instrumentingMiddleware) GetNextCACert(ctx context.Context) (cacert []byte, err error) {
	defer func(begin time.Time) {
		lvs := []string{"method", "GetNextCACert", "error", fmt.Sprint(err != nil)}
		mw.requestCount.With(lvs...).Add(1)
		mw.requestLatency.With(lvs...).Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetNextCACert(ctx)
}
