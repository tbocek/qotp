package qotp

import (
	"errors"
	"log/slog"
	"sync"
)

type StreamState uint8

const (
	StreamStateOpen StreamState = iota
	StreamStateCloseRequest
	StreamStateClosed
	StreamStateCloseReceived
)

var (
	ErrStreamClosed = errors.New("stream closed")
)

type Stream struct {
	streamID uint32
	conn     *Connection
	state    StreamState
	callback func()
	mu       sync.Mutex
}

func (s *Stream) NotifyDataAvailable() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.conn.listener.localConn.TimeoutReadNow()
}

func (s *Stream) CallbackOnWriteBufferAvailable(c func()) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.callback = c
}

func (s *Stream) Read() (userData []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == StreamStateClosed {
		return nil, ErrStreamClosed
	}

	offset, data := s.conn.rcv.RemoveOldestInOrder(s.streamID)
	closeOffset := s.conn.rcv.GetOffsetClosedAt(s.streamID)
	s.conn.updateState(s, closeOffset != nil && *closeOffset == offset)
	slog.Debug("Read", gId(), s.debug(), slog.String("b…", string(data[:min(16, len(data))])))
	return data, nil
}

func (s *Stream) Write(userData []byte) (remainingUserData []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == StreamStateClosed {
		return nil, ErrStreamClosed
	}

	if len(userData) == 0 {
		return userData, nil
	}

	slog.Debug("Write", gId(), s.debug(), slog.String("b…", string(userData[:min(16, len(userData))])))
	n, status := s.conn.snd.QueueData(s.streamID, userData)
	if status != InsertStatusOk {
		slog.Debug("Status Nok", gId(), s.debug(), slog.Any("status", status))
	} else {
		//data is read, so signal to cancel read, since we could do a flush
		err = s.conn.listener.localConn.TimeoutReadNow()
		if err != nil {
			return nil, err
		}
	}

	remainingUserData = userData[n:]
	return remainingUserData, nil
}

func (s *Stream) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = StreamStateCloseRequest
}

func (s *Stream) debug() slog.Attr {
	if s.conn == nil {
		return slog.String("net", "s.conn is nil")
	} else if s.conn.listener == nil {
		return slog.String("net", "s.conn.listener is nil")
	} else if s.conn.listener.localConn == nil {
		return slog.String("net", "s.conn.listener.localConn is nil")
	}

	return slog.String("net", s.conn.listener.localConn.LocalAddrString())
}

func (s *Stream) currentOffset() uint64 {
	streamBuffer := s.conn.snd.streams[s.streamID]
	if streamBuffer == nil {
		return 0
	}
	return streamBuffer.sentOffset
}
