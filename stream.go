package tomtp

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
	streamId uint32
	conn     *Connection
	state    StreamState
	mu       sync.Mutex
}

func (s *Stream) NotifyStreamChange() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.conn.listener.localConn.TimeoutReadNow()
}

func (s *Stream) Read() (readData []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == StreamStateClosed {
		return nil, ErrStreamClosed
	}

	_, data := s.conn.rbRcv.RemoveOldestInOrder(s.streamId)
	if data == nil {
		return nil, nil
	}

	readData = data.data
	s.conn.updateState(s, data.isClose)
	return readData, nil
}

func (s *Stream) Write(writeData []byte) (remainingWriteData []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == StreamStateClosed {
		return nil, ErrStreamClosed
	}

	if len(writeData) == 0 {
		return writeData, nil
	}

	slog.Debug("Write", debugGoroutineID(), s.debug(), slog.String("b...", string(writeData[:min(10, len(writeData))])))
	n, status := s.conn.rbSnd.Insert(s.streamId, writeData)
	if status != InsertStatusOk {
		slog.Debug("Status Nok", debugGoroutineID(), s.debug(), slog.Any("status", status))
	} else {
		//data is read, so signal to cancel read, since we could do a flush
		err = s.conn.listener.localConn.TimeoutReadNow()
		if err != nil {
			return nil, err
		}
	}

	remainingWriteData = writeData[n:]
	return remainingWriteData, nil
}

func (s *Stream) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = StreamStateCloseRequest
}

func (s *Stream) debug() slog.Attr {
	if s.conn == nil {
		return slog.Any("s.conn", "is null")
	} else if s.conn.listener == nil {
		return slog.Any("s.conn.listener", "is null")
	}
	return s.conn.listener.debug(s.conn.remoteAddr)
}

func (s *Stream) currentOffset() uint64 {
	sb := s.conn.rbSnd.streams[s.streamId]
	if sb == nil {
		return 0
	}
	return sb.sentOffset
}
