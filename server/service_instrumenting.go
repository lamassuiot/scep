package scepserver

import (
	"context"
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

func (mw *instrumentingMiddleware) GetCACaps(ctx context.Context) (caps []byte, err error) {
	defer func(begin time.Time) {
		mw.requestCount.With("method", "GetCACaps").Add(1)
		mw.requestLatency.With("method", "GetCACaps").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetCACaps(ctx)
}

func (mw *instrumentingMiddleware) GetCACert(ctx context.Context) (cert []byte, certNum int, err error) {
	defer func(begin time.Time) {
		mw.requestCount.With("method", "GetCACert").Add(1)
		mw.requestLatency.With("method", "GetCACert").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetCACert(ctx)
}

func (mw *instrumentingMiddleware) PKIOperation(ctx context.Context, data []byte) (certRep []byte, err error) {
	defer func(begin time.Time) {
		mw.requestCount.With("method", "PKIOperation").Add(1)
		mw.requestLatency.With("method", "PKIOperation").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.PKIOperation(ctx, data)
}

func (mw *instrumentingMiddleware) GetNextCACert(ctx context.Context) ([]byte, error) {
	defer func(begin time.Time) {
		mw.requestCount.With("method", "GetNextCACert").Add(1)
		mw.requestLatency.With("method", "GetNextCACert").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return mw.next.GetNextCACert(ctx)
}
