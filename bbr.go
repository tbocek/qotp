package tomtp

import (
	"log/slog"
)

type BBRState int

const (
	BBRStateStartup BBRState = iota
	BBRStateNormal
)

type Sample struct {
	sample     uint64
	timeMicros uint64
}

type BBR struct {
	// Core state
	state         BBRState  // Current state (Startup or Normal)
	rttSamples    [5]Sample // Keep 5 lowest RTT samples (rtt=0 means empty)
	bwMax         uint64
	bwDec         uint64
	lastProbeTime uint64 // When we last probed for more bandwidth (microseconds)
	pacingGain    uint64 // Current pacing gain (100 = 1.0x, 277 = 2.77x)
}

// NewBBR creates a new BBR instance with default values
func NewBBR() BBR {
	return BBR{
		state:      BBRStateStartup,
		pacingGain: 277, // BBR's startup gain of 2.77x (https://github.com/google/bbr/blob/master/Documentation/startup/gain/analysis/bbr_startup_gain.pdf)
	}
}

func (c *Connection) UpdateBBR(rttMeasurement uint64, bytesAcked uint64, nowMicros uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. Update RTT samples - keep 5 lowest
	if rttMeasurement == 0 {
		//no measurement, cannot update BBR
		slog.Warn("cannot update BBR, rtt is 0")
		return
	}

	if bytesAcked == 0 {
		//should never happen as also an empty packet has header bytes
		slog.Error("cannot ack 0 bytes")
		return
	}

	replaceIdx := -1
	maxIdx := 0
	for i := 0; i < len(c.BBR.rttSamples); i++ {
		// Remove if older than 10 seconds
		if c.BBR.rttSamples[i].sample > 0 && nowMicros-c.BBR.rttSamples[i].timeMicros >= 10*1000000 {
			c.BBR.rttSamples[i].sample = 0
		}

		// Track first empty slot
		if replaceIdx == -1 && c.BBR.rttSamples[i].sample == 0 {
			replaceIdx = i
		}

		// Track highest RTT slot
		if c.BBR.rttSamples[i].sample > c.BBR.rttSamples[maxIdx].sample {
			maxIdx = i
		}
	}

	// Use empty slot if available, otherwise replace highest if new is lower
	if replaceIdx >= 0 {
		c.BBR.rttSamples[replaceIdx] = Sample{sample: rttMeasurement, timeMicros: nowMicros}
	} else if rttMeasurement < c.BBR.rttSamples[maxIdx].sample {
		c.BBR.rttSamples[maxIdx] = Sample{sample: rttMeasurement, timeMicros: nowMicros}
	}

	rttMin := rttMeasurement // Start with current measurement
	for i := 0; i < len(c.BBR.rttSamples); i++ {
		// Track lowest RTT value
		if c.BBR.rttSamples[i].sample > 0 && c.BBR.rttSamples[i].sample < rttMin {
			rttMin = c.BBR.rttSamples[i].sample
		}
	}

	// 2. Update bwInc/bwDec based on whether we found a new max
	instantBw := bytesAcked * 1000000 / rttMin
	if instantBw > c.BBR.bwMax {
		c.BBR.bwMax = instantBw
		c.BBR.bwDec = 0
	} else {
		c.BBR.bwDec++
	}

	// 3. Initialize on first measurement
	if c.BBR.lastProbeTime == 0 {
		c.BBR.lastProbeTime = nowMicros
	}

	// 4. State-specific behavior
	switch c.BBR.state {
	case BBRStateStartup:
		if c.BBR.bwDec >= 3 {
			c.BBR.state = BBRStateNormal
			c.BBR.pacingGain = 100
		}
	case BBRStateNormal:
		rttRatioPct := (c.RTT.srtt * 100) / rttMin

		if rttRatioPct > 150 {
			c.BBR.pacingGain = 75
		} else if rttRatioPct > 125 {
			c.BBR.pacingGain = 90
		} else if nowMicros-c.BBR.lastProbeTime > rttMin*8 {
			c.BBR.pacingGain = 125
			c.BBR.lastProbeTime = nowMicros
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
		return 10000 // 10ms default
	}

	// Apply pacing gain to bandwidth
	effectiveRate := (c.BBR.bwMax * c.BBR.pacingGain) / 100

	if effectiveRate == 0 {
		return 10000 // 10ms fallback only for truly broken state
	}

	// Calculate inter-packet interval in microseconds
	// packetSize is in bytes, effectiveRate is in bytes/second
	// interval = (packetSize / effectiveRate) * 1,000,000 microseconds/second
	intervalMicros := (packetSize * 1000000) / effectiveRate

	return intervalMicros
}
