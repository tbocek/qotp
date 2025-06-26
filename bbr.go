package tomtp

import (
	"math"
)

type BBRState int

const (
	BBRStateStartup BBRState = iota
	BBRStateNormal
)

type BBR struct {
	// Core state
	state                BBRState // Current state (Startup or Normal)
	rttMin               uint64   // Current minimum RTT estimate
	rttMinDecayFactorPct uint64   // How quickly old minimums fade (smaller = more aggressive)
	bwMax                uint64   // Current maximum bandwidth estimate
	bwMaxDecayFactorPct  uint64   // How quickly old maximums fade (smaller = more aggressive)
	bwInc                uint64
	bwDec                uint64
	lastProbeTime        uint64 // When we last probed for more bandwidth (microseconds)
	pacingGain           uint64 // Current pacing gain (100 = 1.0x, 277 = 2.77x)
}

// NewBBR creates a new BBR instance with default values
func NewBBR() BBR {
	return BBR{
		state:                BBRStateStartup,
		rttMin:               math.MaxUint64,
		rttMinDecayFactorPct: 95, // More aggressive: 0.9, Less aggressive: 0.99
		bwMax:                0,
		bwMaxDecayFactorPct:  95,  // More aggressive: 0.9, Less aggressive: 0.99
		pacingGain:           277, // BBR's startup gain of 2.77x (https://github.com/google/bbr/blob/master/Documentation/startup/gain/analysis/bbr_startup_gain.pdf)
	}
}

func (c *Connection) UpdateBBR(rttMeasurement uint64, bytesAcked uint64, nowMicros uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 1. Update min RTT measurements
	if c.rttMin == math.MaxUint64 {
		c.rttMin = rttMeasurement
	} else {
		// Decay the minimum (allows it to rise if network conditions change)
		c.rttMin = (c.rttMin * c.rttMinDecayFactorPct) / 100
	}
	if rttMeasurement > 0 && rttMeasurement < c.rttMin { // Ignore values more than 10x the min
		c.rttMin = rttMeasurement
	}

	// 2. Update bandwidth estimate
	if c.bwMax > 0 {
		// Decay max bandwidth estimate
		c.bwMax = (c.bwMax * c.bwMaxDecayFactorPct) / 100
	}
	if rttMeasurement > 0 && bytesAcked > 0 {
		instantBw := bytesAcked * 1000000 / rttMeasurement
		if c.bwMax == 0 || c.bwMax < instantBw { //this includes the decay -> more aggressive
			c.bwMax = instantBw
			c.bwInc++
			c.bwDec = 0
		} else {
			c.bwInc = 0
			c.bwDec++
		}
	}

	// 3. State-specific behavior
	switch c.BBR.state {
	case BBRStateStartup:
		// Only exit startup on packet loss or significant RTT increase
		if c.bwDec >= 3 || (c.RTT.srtt/c.rttMin >= 2) {
			c.BBR.state = BBRStateNormal //if the bandwidth did not increase for the 3rd time, slow start is over the next time
			c.BBR.pacingGain = 100       // Switch to 1.0x gain
		}
	case BBRStateNormal:
		// Adjust pacing gain based on conditions
		rttRatioPct := (c.RTT.srtt * 100) / c.BBR.rttMin

		if rttRatioPct > 150 {
			// RTT is inflated, reduce pacing to drain queue
			c.BBR.pacingGain = 75 // 0.75x
		} else if rttRatioPct > 125 {
			// Slight RTT inflation, be conservative
			c.BBR.pacingGain = 90 // 0.9x
		} else if nowMicros-c.BBR.lastProbeTime > c.BBR.rttMin*8 {
			// Periodically probe for more bandwidth every 8 RTTs
			c.BBR.pacingGain = 125 // 1.25x probe
			c.BBR.lastProbeTime = nowMicros
		} else {
			// Normal operation
			c.BBR.pacingGain = 100 // 1.0x
		}
	}
}

func (c *Connection) OnDuplicateAck() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// For pacing-based BBR, duplicate ACKs indicate mild congestion
	// We respond by slightly reducing our bandwidth estimate and pacing gain

	c.BBR.bwMax = c.BBR.bwMax * 97 / 100 // Reduce bandwidth estimate by 3%
	c.BBR.pacingGain = 90                // Reduce pacing to 0.9x

	// Don't necessarily need to change state - dup ACKs are less severe than loss
	// But if we're in startup, this is a sign to exit
	if c.BBR.state == BBRStateStartup {
		c.BBR.state = BBRStateNormal
		c.BBR.pacingGain = 90 // Start normal state conservatively
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
		return c.RTT.srtt / 10
	}

	// Apply pacing gain to bandwidth
	effectiveRate := (c.BBR.bwMax * c.BBR.pacingGain) / 100

	if effectiveRate == 0 {
		return 1000 // 1ms fallback only for truly broken state
	}

	// Calculate inter-packet interval in microseconds
	// packetSize is in bytes, effectiveRate is in bytes/second
	// interval = (packetSize / effectiveRate) * 1,000,000 microseconds/second
	intervalMicros := (packetSize * 1000000) / effectiveRate

	return intervalMicros
}
