// ©AngelaMos | 2026
// readloop.go

package coinbase

import (
	"context"
	"errors"
)

var ErrSequenceGap = errors.New("coinbase: sequence gap detected")

type FrameHandler func(ctx context.Context, f Frame) error

func ReadLoop(ctx context.Context, conn *Conn, seq *Sequencer, handler FrameHandler) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		frame, err := conn.ReadFrame(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}

		switch frame.Kind {
		case FrameTypeUnknown, FrameTypeSubscriptions, FrameTypeHeartbeats:
		case FrameTypeSnapshot:
			seq.Reset()
			for _, t := range frame.Tickers {
				_ = seq.Observe(t.ProductID, frame.SequenceNum)
			}
		case FrameTypeTicker:
			for _, t := range frame.Tickers {
				if seq.Observe(t.ProductID, frame.SequenceNum) {
					return ErrSequenceGap
				}
			}
		}

		if err := handler(ctx, frame); err != nil {
			return err
		}
	}
}
