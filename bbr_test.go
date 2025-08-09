package tomtp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Helper function to create a minimal Connection for testing
func newTestConnection() *Connection {
	return &Connection{
		BBR: NewBBR(),
		RTT: RTT{
			srtt:   0,
			rttvar: 0,
		},
	}
}

// TestUpdateBBR_InvalidInputs verifies that invalid inputs are handled correctly
func TestUpdateBBR_InvalidInputs(t *testing.T) {
	conn := newTestConnection()

	// Test zero RTT measurement
	conn.UpdateBBR(0, 1000, 1000000000)
	assert.Equal(t, uint64(0), conn.BBR.bwMax, "Bandwidth should not update with zero RTT")

	// Test zero bytes acked
	conn.UpdateBBR(100000000, 0, 1000000000)
	assert.Equal(t, uint64(0), conn.BBR.bwMax, "Bandwidth should not update with zero bytes")
}

// TestUpdateBBR_FirstMeasurement verifies the first RTT measurement behavior
func TestUpdateBBR_FirstMeasurement(t *testing.T) {
	conn := newTestConnection()
	conn.RTT.srtt = 50000000 // 50ms in nanoseconds

	// First RTT measurement
	conn.UpdateBBR(100000000, 1000, 1000000000) // 100ms RTT, 1000 bytes, at 1 second

	// Check that RTT was stored
	assert.Equal(t, uint64(100000000), conn.BBR.rttMinNano, "First RTT should be stored as minimum")
	assert.Equal(t, uint64(1000000000), conn.BBR.rttMinTimeNano, "Timestamp should be stored")

	// Check bandwidth calculation: 1000 bytes * 1000 / (100ms / 1000ms) = 10000 bytes/sec
	assert.Equal(t, uint64(10000), conn.BBR.bwMax, "Bandwidth should be calculated correctly")
	assert.Equal(t, uint64(0), conn.BBR.bwDec, "bwDec should be 0 after bandwidth increase")
	assert.Equal(t, BBRStateStartup, conn.BBR.state, "Should remain in startup state")
	assert.Equal(t, uint64(277), conn.BBR.pacingGain, "Should maintain startup gain")
}

// TestUpdateBBR_RTTMinTracking verifies that minimum RTT is tracked correctly
func TestUpdateBBR_RTTMinTracking(t *testing.T) {
	conn := newTestConnection()
	conn.RTT.srtt = 50000000 // 50ms in nanoseconds

	// Add initial RTT measurement
	conn.UpdateBBR(100000000, 1000, 1000000000) // 100ms
	assert.Equal(t, uint64(100000000), conn.BBR.rttMinNano, "Initial RTT should be stored")

	// Add higher RTT - should not replace minimum
	conn.UpdateBBR(150000000, 1000, 2000000000) // 150ms
	assert.Equal(t, uint64(100000000), conn.BBR.rttMinNano, "Minimum RTT should not change")

	// Add lower RTT - should replace minimum
	conn.UpdateBBR(50000000, 1000, 3000000000) // 50ms
	assert.Equal(t, uint64(50000000), conn.BBR.rttMinNano, "Lower RTT should become new minimum")
	assert.Equal(t, uint64(3000000000), conn.BBR.rttMinTimeNano, "Timestamp should be updated")
}

// TestUpdateBBR_RTTMinExpiry verifies that old RTT minimum expires after 10 seconds
func TestUpdateBBR_RTTMinExpiry(t *testing.T) {
	conn := newTestConnection()
	conn.RTT.srtt = 50000000 // 50ms in nanoseconds

	// Add an RTT sample
	conn.UpdateBBR(100000000, 1000, 1000000000) // 100ms at 1 second
	assert.Equal(t, uint64(100000000), conn.BBR.rttMinNano, "RTT should be stored")

	// Update within 10 seconds - old min should persist if new RTT is higher
	conn.UpdateBBR(150000000, 1000, 9000000000) // 150ms at 9 seconds
	assert.Equal(t, uint64(100000000), conn.BBR.rttMinNano, "Min RTT should persist within 10 seconds")

	// Update after 10 seconds - should take new measurement even if higher
	conn.UpdateBBR(120000000, 1000, 11000000001) // 120ms at 11+ seconds
	assert.Equal(t, uint64(120000000), conn.BBR.rttMinNano, "RTT min should update after 10 seconds")
	assert.Equal(t, uint64(11000000001), conn.BBR.rttMinTimeNano, "Timestamp should be updated")
}

// TestUpdateBBR_BandwidthCalculation verifies bandwidth is calculated using minimum RTT
func TestUpdateBBR_BandwidthCalculation(t *testing.T) {
	conn := newTestConnection()
	conn.RTT.srtt = 50000000 // 50ms in nanoseconds

	// Add multiple RTT measurements
	conn.UpdateBBR(100000000, 1000, 1000000000) // 100ms - becomes min
	assert.Equal(t, uint64(10000), conn.BBR.bwMax, "Initial bandwidth with 100ms RTT")

	conn.UpdateBBR(50000000, 1000, 2000000000) // 50ms - new min
	// Bandwidth should be recalculated: 1000 bytes * 1000 / (50ms / 1000ms) = 20000 bytes/sec
	assert.Equal(t, uint64(20000), conn.BBR.bwMax, "Bandwidth should use new minimum RTT")

	conn.UpdateBBR(75000000, 1000, 3000000000) // 75ms - not new min
	// Bandwidth still calculated with 50ms min: 20000 bytes/sec
	assert.Equal(t, uint64(20000), conn.BBR.bwMax, "Bandwidth should still use 50ms minimum")
}

// TestUpdateBBR_BandwidthTracking verifies bandwidth max tracking
func TestUpdateBBR_BandwidthTracking(t *testing.T) {
	conn := newTestConnection()
	conn.RTT.srtt = 50000000 // 50ms in nanoseconds

	// First measurement establishes baseline
	conn.UpdateBBR(50000000, 1000, 1000000000) // 20KB/s
	assert.Equal(t, uint64(20000), conn.BBR.bwMax, "Initial bandwidth")
	assert.Equal(t, uint64(0), conn.BBR.bwDec, "bwDec should be 0")

	// Higher bandwidth measurement
	conn.UpdateBBR(50000000, 2000, 2000000000) // 40KB/s (2000 bytes with same 50ms min RTT)
	assert.Equal(t, uint64(40000), conn.BBR.bwMax, "Bandwidth should increase")
	assert.Equal(t, uint64(0), conn.BBR.bwDec, "bwDec should reset to 0")

	// Lower bandwidth measurement
	conn.UpdateBBR(50000000, 1000, 3000000000) // 20KB/s
	assert.Equal(t, uint64(40000), conn.BBR.bwMax, "Bandwidth max should not decrease")
	assert.Equal(t, uint64(1), conn.BBR.bwDec, "bwDec should increment")
}

// TestUpdateBBR_StartupToNormalTransition verifies transition when bandwidth plateaus
func TestUpdateBBR_StartupToNormalTransition(t *testing.T) {
	conn := newTestConnection()
	conn.RTT.srtt = 50000000 // 50ms in nanoseconds

	// Establish baseline bandwidth
	conn.UpdateBBR(50000000, 2000, 1000000000) // 40KB/s
	assert.Equal(t, BBRStateStartup, conn.BBR.state, "Should be in startup")

	// Three consecutive measurements without bandwidth increase
	for i := 1; i <= 3; i++ {
		conn.UpdateBBR(50000000, 1000, uint64(1000000000+i*1000000000)) // Lower bandwidth
		if i < 3 {
			assert.Equal(t, BBRStateStartup, conn.BBR.state, "Should remain in startup")
		}
	}

	// After 3 decreases, should transition
	assert.Equal(t, BBRStateNormal, conn.BBR.state, "Should transition to normal after 3 bwDec")
	assert.Equal(t, uint64(100), conn.BBR.pacingGain, "Pacing gain should be 1.0x")
}

// TestUpdateBBR_NormalStateRTTBased verifies normal state RTT-based pacing adjustments
func TestUpdateBBR_NormalStateRTTBased(t *testing.T) {
	conn := newTestConnection()
	conn.BBR.state = BBRStateNormal
	conn.BBR.bwMax = 10000
	conn.BBR.rttMinNano = 100000000        // Set min RTT to 100ms
	conn.BBR.rttMinTimeNano = 1000000000   // Set time for min RTT
	conn.BBR.lastProbeTime = 1000000000    // Initialize to prevent probing

	// Test high RTT inflation (SRTT > 1.5x min)
	conn.RTT.srtt = 160000000                // 160ms
	conn.UpdateBBR(200000000, 1000, 1100000000) // New measurement won't replace min
	assert.Equal(t, uint64(75), conn.BBR.pacingGain, "Should reduce to 75% when RTT > 1.5x min")

	// Test moderate RTT inflation (SRTT > 1.25x min)
	conn.RTT.srtt = 130000000                // 130ms
	conn.UpdateBBR(200000000, 1000, 1200000000)
	assert.Equal(t, uint64(90), conn.BBR.pacingGain, "Should reduce to 90% when RTT > 1.25x min")

	// Test normal RTT (ensure we're not in probe window)
	conn.RTT.srtt = 100000000                // 100ms
	conn.BBR.lastProbeTime = 1200000000      // Recent probe time
	conn.UpdateBBR(200000000, 1000, 1300000000) // Only 100ms later (1 RTT, not 8)
	assert.Equal(t, uint64(100), conn.BBR.pacingGain, "Should be 100% when RTT is normal")
}

// TestUpdateBBR_BandwidthProbing verifies periodic bandwidth probing
func TestUpdateBBR_BandwidthProbing(t *testing.T) {
	conn := newTestConnection()
	conn.BBR.state = BBRStateNormal
	conn.BBR.bwMax = 10000
	conn.BBR.rttMinNano = 100000000        // 100ms min RTT
	conn.BBR.rttMinTimeNano = 1000000000
	conn.RTT.srtt = 100000000              // 100ms
	conn.BBR.lastProbeTime = 1000000000

	// Update before probe time (less than 8 RTTs = 800ms)
	conn.UpdateBBR(150000000, 1000, 1500000000) // 0.5 seconds = 5 RTTs
	assert.Equal(t, uint64(100), conn.BBR.pacingGain, "Should not probe yet")

	// Update after probe time (more than 8 RTTs = 800ms)
	conn.UpdateBBR(150000000, 1000, 1900000000) // 0.9 seconds = 9 RTTs since last probe
	assert.Equal(t, uint64(125), conn.BBR.pacingGain, "Should probe with 125% gain")
	assert.Equal(t, uint64(1900000000), conn.BBR.lastProbeTime, "Should update probe time")
}

// TestOnDuplicateAck verifies duplicate ACK handling
func TestOnDuplicateAck(t *testing.T) {
	// Test in startup state
	conn := newTestConnection()
	conn.BBR.bwMax = 10000
	conn.OnDuplicateAck()

	assert.Equal(t, BBRStateNormal, conn.BBR.state, "Should exit startup on dup ACK")
	assert.Equal(t, uint64(9800), conn.BBR.bwMax, "Bandwidth should reduce by 2%")
	assert.Equal(t, uint64(90), conn.BBR.pacingGain, "Should set gain to 90%")

	// Test in normal state
	conn2 := newTestConnection()
	conn2.BBR.state = BBRStateNormal
	conn2.BBR.bwMax = 10000
	conn2.OnDuplicateAck()

	assert.Equal(t, BBRStateNormal, conn2.BBR.state, "Should remain in normal state")
	assert.Equal(t, uint64(9800), conn2.BBR.bwMax, "Bandwidth should reduce by 2%")
}

// TestOnPacketLoss verifies packet loss handling
func TestOnPacketLoss(t *testing.T) {
	conn := newTestConnection()
	conn.BBR.bwMax = 10000

	conn.OnPacketLoss()

	assert.Equal(t, BBRStateNormal, conn.BBR.state, "Should switch to normal state")
	assert.Equal(t, uint64(9500), conn.BBR.bwMax, "Bandwidth should reduce by 5%")
	assert.Equal(t, uint64(100), conn.BBR.pacingGain, "Should reset gain to 100%")
}

// TestGetPacingInterval_NoBandwidth verifies pacing when no bandwidth estimate exists
func TestGetPacingInterval_NoBandwidth(t *testing.T) {
	conn := newTestConnection()

	// Test with no SRTT
	interval := conn.GetPacingInterval(1000)
	assert.Equal(t, uint64(10000), interval, "Should return 10ms default when no SRTT")

	// Test with SRTT but no bandwidth
	conn.RTT.srtt = 100000000 // 100ms in nanoseconds
	interval = conn.GetPacingInterval(1000)
	assert.Equal(t, uint64(10000000), interval, "Should return SRTT/10 when no bandwidth")
}

// TestGetPacingInterval_WithBandwidth verifies normal pacing calculation
func TestGetPacingInterval_WithBandwidth(t *testing.T) {
	conn := newTestConnection()
	conn.BBR.bwMax = 10000    // 10KB/s
	conn.BBR.pacingGain = 100 // 1.0x

	// 1KB packet: (1000 bytes / 10000 bytes/sec) * 1e9 ns = 100,000,000 ns
	interval := conn.GetPacingInterval(1000)
	assert.Equal(t, uint64(100000000), interval, "Should calculate correct interval")

	// Test with pacing gain
	conn.BBR.pacingGain = 200 // 2.0x
	interval = conn.GetPacingInterval(1000)
	assert.Equal(t, uint64(50000000), interval, "Higher gain should reduce interval")

	// Test with very low pacing gain
	conn.BBR.pacingGain = 50 // 0.5x
	interval = conn.GetPacingInterval(1000)
	assert.Equal(t, uint64(200000000), interval, "Lower gain should increase interval")
}

// TestGetPacingInterval_EdgeCases verifies edge case handling
func TestGetPacingInterval_EdgeCases(t *testing.T) {
	conn := newTestConnection()

	// Test with zero effective rate
	conn.BBR.bwMax = 10000
	conn.BBR.pacingGain = 0 // Would make effective rate 0
	interval := conn.GetPacingInterval(1000)
	assert.Equal(t, uint64(10000), interval, "Should return 10ms fallback")

	// Test with very small packet
	conn.BBR.pacingGain = 100
	interval = conn.GetPacingInterval(1) // 1 byte
	assert.Equal(t, uint64(100000), interval, "Should handle small packets")
}

// TestBBRIntegration verifies complete BBR flow
func TestBBRIntegration(t *testing.T) {
	conn := newTestConnection()
	conn.RTT.srtt = 50000000 // 50ms in nanoseconds

	// Startup phase - increasing bandwidth
	for i := 0; i < 5; i++ {
		conn.UpdateBBR(50000000, uint64(1000*(i+1)), uint64(1000000000*(i+1)))
	}
	assert.Equal(t, BBRStateStartup, conn.BBR.state, "Should still be in startup")

	// Plateau - trigger transition
	for i := 0; i < 3; i++ {
		conn.UpdateBBR(50000000, 1000, uint64(6000000000+i*1000000000))
	}
	assert.Equal(t, BBRStateNormal, conn.BBR.state, "Should transition to normal")

	// Verify pacing calculation works
	interval := conn.GetPacingInterval(1000)
	assert.Greater(t, interval, uint64(0), "Should calculate valid pacing interval")
}