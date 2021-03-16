package api

import (
	"context"
	"time"

	"github.com/go-kit/kit/log"
)

type Middleware func(Service) Service

func LoggingMidleware(logger log.Logger) Middleware {
	return func(next Service) Service {
		return &loggingMidleware{
			next:   next,
			logger: logger,
		}
	}
}

type loggingMidleware struct {
	next   Service
	logger log.Logger
}

func (mw loggingMidleware) Health(ctx context.Context) (healthy bool) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "Health",
			"took", time.Since(begin),
			"healthy", healthy,
		)
	}(time.Now())
	return mw.next.Health(ctx)
}

func (mw loggingMidleware) PostGetCRT(ctx context.Context, csrData []byte) (crtData []byte, err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "PostGetCRT",
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return mw.next.PostGetCRT(ctx, csrData)
}

func (mw loggingMidleware) PostSetConfig(ctx context.Context, CA string) (err error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "PostSetConfig",
			"request_ca", CA,
			"took", time.Since(begin),
			"err", err,
		)
	}(time.Now())
	return mw.next.PostSetConfig(ctx, CA)
}
