// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Wojciech Polak

package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ErrIdleTimeout reports a relay that moved no bytes before its idle limit.
var ErrIdleTimeout = errors.New("relay idle timeout")

// Options bounds one bidirectional relay.
type Options struct {
	IdleTimeout time.Duration
	MaxLifetime time.Duration
}

// Copy moves bytes in both directions until both sides reach EOF, an I/O error
// occurs, the context is cancelled, or a configured timeout expires. A clean
// EOF half-closes the opposite writer and leaves the reverse copy running.
func Copy(ctx context.Context, left, right net.Conn, options Options) error {
	if left == nil || right == nil {
		return errors.New("relay requires two connections")
	}
	if options.IdleTimeout < 0 || options.MaxLifetime < 0 {
		return errors.New("relay timeouts must not be negative")
	}
	if options.MaxLifetime > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.MaxLifetime)
		defer cancel()
	}

	activity := make(chan struct{}, 1)
	interrupted := make(chan error, 1)
	watchDone := make(chan struct{})
	var watch sync.WaitGroup
	watch.Add(1)
	go func() {
		defer watch.Done()
		watchRelay(ctx, left, right, options.IdleTimeout, activity, interrupted, watchDone)
	}()
	defer func() {
		close(watchDone)
		watch.Wait()
	}()

	touch := func() {
		select {
		case activity <- struct{}{}:
		default:
		}
	}
	leftStream := progressConn{Conn: left, touch: touch}
	rightStream := progressConn{Conn: right, touch: touch}
	touch()

	results := make(chan error, 2)
	go copyDirection(results, &rightStream, &leftStream)
	go copyDirection(results, &leftStream, &rightStream)
	first := <-results
	if first != nil {
		interruptConnections(left, right)
	}
	second := <-results

	select {
	case err := <-interrupted:
		return err
	default:
	}
	return errors.Join(first, second)
}

type progressConn struct {
	net.Conn
	touch func()
}

func (c *progressConn) Read(buffer []byte) (int, error) {
	count, err := c.Conn.Read(buffer)
	if count > 0 {
		c.touch()
	}
	return count, err
}

func (c *progressConn) Write(buffer []byte) (int, error) {
	count, err := c.Conn.Write(buffer)
	if count > 0 {
		c.touch()
	}
	return count, err
}

func copyDirection(results chan<- error, destination, source *progressConn) {
	_, err := io.Copy(destination, source)
	if err == nil {
		halfCloseWrite(destination.Conn)
		halfCloseRead(source.Conn)
	}
	results <- err
}

func halfCloseWrite(conn net.Conn) {
	if closer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
}

func halfCloseRead(conn net.Conn) {
	if closer, ok := conn.(interface{ CloseRead() error }); ok {
		_ = closer.CloseRead()
	}
}

func watchRelay(
	ctx context.Context,
	left, right net.Conn,
	idle time.Duration,
	activity <-chan struct{},
	interrupted chan<- error,
	done <-chan struct{},
) {
	var timer *time.Timer
	var timerChannel <-chan time.Time
	if idle > 0 {
		timer = time.NewTimer(idle)
		timerChannel = timer.C
		defer timer.Stop()
	}
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			select {
			case interrupted <- ctx.Err():
			default:
			}
			interruptConnections(left, right)
			return
		case <-activity:
			if timer != nil {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(idle)
			}
		case <-timerChannel:
			select {
			case interrupted <- fmt.Errorf("%w after %s", ErrIdleTimeout, idle):
			default:
			}
			interruptConnections(left, right)
			return
		}
	}
}

func interruptConnections(connections ...net.Conn) {
	deadline := time.Unix(1, 0)
	for _, conn := range connections {
		_ = conn.SetDeadline(deadline)
	}
}
