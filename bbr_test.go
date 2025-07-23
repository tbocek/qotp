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
	conn.UpdateBBR(0, 1000, 1000000)
	assert.Equal(t, uint64(0), conn.BBR.bwMax, "Bandwidth should not update with zero RTT")

	// Test zero bytes acked
	conn.UpdateBBR(100000, 0, 1000000)
	assert.Equal(t, uint64(0), conn.BBR.bwMax, "Bandwidth should not update with zero bytes")
}

// TestUpdateBBR_FirstMeasurement verifies the first RTT measurement behavior
func TestUpdateBBR_FirstMeasurement(t *testing.T) {
	conn := newTestConnection()
	conn.RTT.srtt = 50000 // 50ms

	// First RTT measurement
	conn.UpdateBBR(100000, 1000, 1000000) // 100ms RTT, 1000 bytes, at 1 second

	// Check that RTT was stored
	assert.Equal(t, uint64(100000), conn.BBR.rttSamples[0].sample, "First RTT should be stored")
	assert.Equal(t, uint64(1000000), conn.BBR.rttSamples[0].timeMicros, "Timestamp should be stored")

	// Check bandwidth calculation: 1000 bytes * 1M µs / 100000 µs = 10000 bytes/sec
	assert.Equal(t, uint64(10000), conn.BBR.bwMax, "Bandwidth should be calculated correctly")
	assert.Equal(t, uint64(0), conn.BBR.bwDec, "bwDec should be 0 after bandwidth increase")
	assert.Equal(t, BBRStateStartup, conn.BBR.state, "Should remain in startup state")
	assert.Equal(t, uint64(277), conn.BBR.pacingGain, "Should maintain startup gain")
}

// TestUpdateBBR_RTTSampleManagement verifies that RTT samples are managed correctly
func TestUpdateBBR_RTTSampleManagement(t *testing.T) {
	conn := newTestConnection()
	conn.RTT.srtt = 50000

	// Fill all 5 RTT slots
	for i := 0; i < 5; i++ {
		conn.UpdateBBR(uint64(100000+i*10000), 1000, uint64(1000000+i*1000000))
	}

	// Verify all slots are filled
	for i := 0; i < 5; i++ {
		assert.NotEqual(t, uint64(0), conn.BBR.rttSamples[i].sample, "Slot %d should be filled", i)
	}

	// Add a lower RTT - should replace the highest
	conn.UpdateBBR(50000, 1000, 6000000)

	// Check that 50000 is now in the samples
	found := false
	for i := 0; i < 5; i++ {
		if conn.BBR.rttSamples[i].sample == 50000 {
			found = true
			break
		}
	}
	assert.True(t, found, "Lower RTT should replace highest RTT in samples")
}

// TestUpdateBBR_RTTSampleExpiry verifies that old RTT samples expire
func TestUpdateBBR_RTTSampleExpiry(t *testing.T) {
	conn := newTestConnection()
	conn.RTT.srtt = 50000

	// Add an RTT sample
	conn.UpdateBBR(100000, 1000, 1000000)
	assert.Equal(t, uint64(100000), conn.BBR.rttSamples[0].sample, "RTT should be stored")

	// Update 11 seconds later - old sample should expire
	conn.UpdateBBR(50000, 1000, 12000000) // 12 seconds

	// Old sample should be cleared, new one stored
	assert.Equal(t, uint64(50000), conn.BBR.rttSamples[0].sample, "Expired slot should be reused")
}

// TestUpdateBBR_MinRTTCalculation verifies minimum RTT is calculated correctly
func TestUpdateBBR_MinRTTCalculation(t *testing.T) {
	conn := newTestConnection()
	conn.RTT.srtt = 50000

	// Add multiple RTT measurements
	conn.UpdateBBR(100000, 1000, 1000000) // 100ms
	conn.UpdateBBR(50000, 1000, 2000000)  // 50ms
	conn.UpdateBBR(75000, 1000, 3000000)  // 75ms

	// Bandwidth should be calculated using minimum RTT (50ms)
	// 1000 bytes * 1M µs / 50000 µs = 20000 bytes/sec
	assert.Equal(t, uint64(20000), conn.BBR.bwMax, "Bandwidth should use minimum RTT")
}

// TestUpdateBBR_BandwidthTracking verifies bandwidth max tracking
func TestUpdateBBR_BandwidthTracking(t *testing.T) {
	conn := newTestConnection()
	conn.RTT.srtt = 50000

	// First measurement establishes baseline
	conn.UpdateBBR(50000, 1000, 1000000) // 20KB/s
	assert.Equal(t, uint64(20000), conn.BBR.bwMax, "Initial bandwidth")
	assert.Equal(t, uint64(0), conn.BBR.bwDec, "bwDec should be 0")

	// Higher bandwidth measurement
	conn.UpdateBBR(50000, 2000, 2000000) // 40KB/s
	assert.Equal(t, uint64(40000), conn.BBR.bwMax, "Bandwidth should increase")
	assert.Equal(t, uint64(0), conn.BBR.bwDec, "bwDec should reset to 0")

	// Lower bandwidth measurement
	conn.UpdateBBR(50000, 1000, 3000000) // 20KB/s
	assert.Equal(t, uint64(40000), conn.BBR.bwMax, "Bandwidth max should not decrease")
	assert.Equal(t, uint64(1), conn.BBR.bwDec, "bwDec should increment")
}

// TestUpdateBBR_StartupToNormalTransition verifies transition when bandwidth plateaus
func TestUpdateBBR_StartupToNormalTransition(t *testing.T) {
	conn := newTestConnection()
	conn.RTT.srtt = 50000

	// Establish baseline bandwidth
	conn.UpdateBBR(50000, 2000, 1000000) // 40KB/s
	assert.Equal(t, BBRStateStartup, conn.BBR.state, "Should be in startup")

	// Three consecutive measurements without bandwidth increase
	for i := 1; i <= 3; i++ {
		conn.UpdateBBR(50000, 1000, uint64(1000000+i*1000000)) // Lower bandwidth
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
	conn.BBR.lastProbeTime = 1000000 // Initialize to prevent probing

	// Test high RTT inflation (SRTT > 1.5x min)
	conn.RTT.srtt = 160000                // 160ms
	conn.UpdateBBR(100000, 1000, 1100000) // min RTT will be 100ms
	assert.Equal(t, uint64(75), conn.BBR.pacingGain, "Should reduce to 75% when RTT > 1.5x min")

	// Test moderate RTT inflation (SRTT > 1.25x min)
	conn.RTT.srtt = 130000 // 130ms
	conn.UpdateBBR(100000, 1000, 1200000)
	assert.Equal(t, uint64(90), conn.BBR.pacingGain, "Should reduce to 90% when RTT > 1.25x min")

	// Test normal RTT (ensure we're not in probe window)
	conn.RTT.srtt = 100000                // 100ms
	conn.BBR.lastProbeTime = 1200000      // Recent probe time
	conn.UpdateBBR(100000, 1000, 1300000) // Only 100ms later (1 RTT, not 8)
	assert.Equal(t, uint64(100), conn.BBR.pacingGain, "Should be 100% when RTT is normal")
}

// TestUpdateBBR_BandwidthProbing verifies periodic bandwidth probing
func TestUpdateBBR_BandwidthProbing(t *testing.T) {
	conn := newTestConnection()
	conn.BBR.state = BBRStateNormal
	conn.BBR.bwMax = 10000
	conn.RTT.srtt = 100000 // 100ms
	conn.BBR.lastProbeTime = 1000000

	// Update before probe time (less than 8 RTTs)
	conn.UpdateBBR(100000, 1000, 1500000) // 0.5 seconds = 5 RTTs
	assert.Equal(t, uint64(100), conn.BBR.pacingGain, "Should not probe yet")

	// Update after probe time (more than 8 RTTs)
	conn.UpdateBBR(100000, 1000, 2000000) // 1 second = 10 RTTs since last probe
	assert.Equal(t, uint64(125), conn.BBR.pacingGain, "Should probe with 125% gain")
	assert.Equal(t, uint64(2000000), conn.BBR.lastProbeTime, "Should update probe time")
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
	conn.RTT.srtt = 100000 // 100ms
	interval = conn.GetPacingInterval(1000)
	assert.Equal(t, uint64(10000), interval, "Should return SRTT/10 when no bandwidth")
}

// TestGetPacingInterval_WithBandwidth verifies normal pacing calculation
func TestGetPacingInterval_WithBandwidth(t *testing.T) {
	conn := newTestConnection()
	conn.BBR.bwMax = 10000    // 10KB/s
	conn.BBR.pacingGain = 100 // 1.0x

	// 1KB packet: (1000 bytes / 10000 bytes/sec) * 1M µs = 100,000 µs
	interval := conn.GetPacingInterval(1000)
	assert.Equal(t, uint64(100000), interval, "Should calculate correct interval")

	// Test with pacing gain
	conn.BBR.pacingGain = 200 // 2.0x
	interval = conn.GetPacingInterval(1000)
	assert.Equal(t, uint64(50000), interval, "Higher gain should reduce interval")

	// Test with very low pacing gain
	conn.BBR.pacingGain = 50 // 0.5x
	interval = conn.GetPacingInterval(1000)
	assert.Equal(t, uint64(200000), interval, "Lower gain should increase interval")
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
	assert.Equal(t, uint64(100), interval, "Should handle small packets")
}

// TestBBRIntegration verifies complete BBR flow
func TestBBRIntegration(t *testing.T) {
	conn := newTestConnection()
	conn.RTT.srtt = 50000

	// Startup phase - increasing bandwidth
	for i := 0; i < 5; i++ {
		conn.UpdateBBR(50000, uint64(1000*(i+1)), uint64(1000000*(i+1)))
	}
	assert.Equal(t, BBRStateStartup, conn.BBR.state, "Should still be in startup")

	// Plateau - trigger transition
	for i := 0; i < 3; i++ {
		conn.UpdateBBR(50000, 1000, uint64(6000000+i*1000000))
	}
	assert.Equal(t, BBRStateNormal, conn.BBR.state, "Should transition to normal")

	// Verify pacing calculation works
	interval := conn.GetPacingInterval(1000)
	assert.Greater(t, interval, uint64(0), "Should calculate valid pacing interval")
}
