package tomtp

import (
	"log/slog"
	"math"
)

type BBRState int

const (
	BBRStateStartup BBRState = iota
	BBRStateNormal
)

type BBR struct {
	// Core state
	state          BBRState // Current state (Startup or Normal)
	rttMinNano     uint64   // Keep lowest RTT samples (rtt=maxuint64 means empty)
	rttMinTimeNano uint64   // When we observed the lowest RTT sample
	bwMax          uint64   // Bytes per second
	bwDec          uint64
	lastProbeTime  uint64 // When we last probed for more bandwidth (nanoeconds)
	pacingGain     uint64 // Current pacing gain (100 = 1.0x, 277 = 2.77x)
}

// NewBBR creates a new BBR instance with default values
func NewBBR() BBR {
	return BBR{
		state:          BBRStateStartup,
		pacingGain:     277, // BBR's startup gain of 2.77x (https://github.com/google/bbr/blob/master/Documentation/startup/gain/analysis/bbr_startup_gain.pdf)
		rttMinNano:     math.MaxUint64,
		rttMinTimeNano: math.MaxUint64,
	}
}

func (c *Connection) UpdateBBR(rttMeasurementNano uint64, bytesAcked uint64, nowNano uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. Update RTT samples - keep current
	if rttMeasurementNano == 0 {
		//no measurement, cannot update BBR
		slog.Warn("cannot update BBR, rtt is 0")
		return
	}

	if bytesAcked == 0 {
		//should never happen as also an empty packet has header bytes
		slog.Error("cannot ack 0 bytes")
		return
	}

	if nowNano-c.BBR.rttMinTimeNano >= 10*secondNano || // Current sample is too old or
		rttMeasurementNano < c.BBR.rttMinNano { // Or we have a better sample
		c.BBR.rttMinNano = rttMeasurementNano
		c.BBR.rttMinTimeNano = nowNano
	}

	// 2. Update bwInc/bwDec based on whether we found a new max
	instantBw := (bytesAcked * 1_000_000) / (c.BBR.rttMinNano / 1000)
	if instantBw > c.BBR.bwMax {
		c.BBR.bwMax = instantBw
		c.BBR.bwDec = 0
	} else {
		c.BBR.bwDec++
	}

	// 3. Initialize on first measurement
	if c.BBR.lastProbeTime == 0 {
		c.BBR.lastProbeTime = nowNano
	}

	// 4. State-specific behavior
	switch c.BBR.state {
	case BBRStateStartup:
		if c.BBR.bwDec >= 3 {
			c.BBR.state = BBRStateNormal
			c.BBR.pacingGain = 100
		}
	case BBRStateNormal:
		rttRatioPct := (c.RTT.srtt * 100) / c.BBR.rttMinNano

		if rttRatioPct > 150 {
			c.BBR.pacingGain = 75
		} else if rttRatioPct > 125 {
			c.BBR.pacingGain = 90
		} else if nowNano-c.BBR.lastProbeTime > c.BBR.rttMinNano*8 {
			c.BBR.pacingGain = 125
			c.BBR.lastProbeTime = nowNano
		} else {
			c.BBR.pacingGain = 100
		}
	}
}

func (c *Connection) OnDuplicateAck() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// For pacing-based BBR, duplicate ACKs indicate mild congestion
	// We respond by slightly reducing our bandwidth estimate and pacing gain
	c.BBR.bwMax = c.BBR.bwMax * 98 / 100 // Reduce bandwidth estimate by 2%
	c.BBR.pacingGain = 90                // Reduce pacing to 0.9x

	// Don't necessarily need to change state - dup ACKs are less severe than loss
	// But if we're in startup, this is a sign to exit
	if c.BBR.state == BBRStateStartup {
		c.BBR.state = BBRStateNormal
	}
}

func (c *Connection) OnPacketLoss() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.BBR.bwMax = c.BBR.bwMax * 95 / 100 // Reduce by 5%
	c.BBR.pacingGain = 100               // Reset to 1.0x
	c.BBR.state = BBRStateNormal
}

func (c *Connection) GetPacingInterval(packetSize uint64) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.BBR.bwMax == 0 {
		// For post-handshake: spread 10 packets over measured RTT
		if c.RTT.srtt > 0 {
			return c.RTT.srtt / 10
		}
		return 10 * msNano // 10ms default
	}

	// Apply pacing gain to bandwidth
	effectiveRate := (c.BBR.bwMax * c.BBR.pacingGain) / 100

	if effectiveRate < 1000 {
		return 10 * msNano // 10ms fallback only for truly broken state
	}

	// Calculate inter-packet interval in nanoseconds
	// packetSize is in bytes, effectiveRate is in bytes/second
	// interval = (packetSize / effectiveRate) * 1,000,000 nanoseconds/second
	intervalNano := (packetSize * 1_000_000_000) / effectiveRate

	return intervalNano
}
