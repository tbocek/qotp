package tomtp

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestFirstRTTMeasurement tests the initial RTT measurement case
func TestFirstRTTMeasurement(t *testing.T) {
	// Create a new connection
	rtt := &RTT{
		srtt:   0,
		rttvar: 0,
	}
	conn := Connection{RTT: *rtt}

	// Update RTT with first measurement
	measurement := uint64(100 * msNano)
	conn.UpdateRTT(measurement)

	// Expected values
	expectedRTT := uint64(100 * msNano)
	expectedVar := uint64(50 * msNano)

	// Validate results
	assert.Equal(t, expectedRTT, conn.srtt, "RTT should match expected value")
	assert.Equal(t, expectedVar, conn.rttvar, "RTT variance should match expected value")
}

// TestIncreasingRTT tests when RTT increases from previous measurement
func TestIncreasingRTT(t *testing.T) {
	// Create a new connection
	rtt := &RTT{
		srtt:   100 * msNano,
		rttvar: 50 * msNano,
	}
	conn := Connection{RTT: *rtt}

	// Update RTT with increased measurement
	measurement := uint64(200 * msNano)
	conn.UpdateRTT(measurement)

	// Expected values - 7/8 * 100ms + 1/8 * 200ms = 112.5ms
	expectedRTT := uint64(112500 * 1000)
	// (50ms*6)/8 + (100ms*2)/8 = 62.5ms
	expectedVar := uint64(62500 * 1000)

	assert.Equal(t, expectedRTT, conn.srtt, "RTT should match expected value")
	assert.Equal(t, expectedVar, conn.rttvar, "RTT variance should match expected value")
}

// TestDecreasingRTT tests when RTT decreases from previous measurement
func TestDecreasingRTT(t *testing.T) {
	// Create a new connection
	rtt := &RTT{
		srtt:   200 * msNano,
		rttvar: 80 * msNano,
	}
	conn := Connection{RTT: *rtt}

	// Update RTT with decreased measurement
	measurement := uint64(100 * msNano)
	conn.UpdateRTT(measurement)

	// Expected values - 7/8 * 200ms + 1/8 * 100ms = 187.5ms
	expectedRTT := uint64(187500 * 1000)
	// (80ms*6)/8 + (100ms*2)/8 = 85ms
	expectedVar := uint64(85 * msNano)

	assert.Equal(t, expectedRTT, conn.srtt, "RTT should match expected value")
	assert.Equal(t, expectedVar, conn.rttvar, "RTT variance should match expected value")
}

// TestStableRTT tests when RTT remains stable
func TestStableRTT(t *testing.T) {
	// Create a new connection
	rtt := &RTT{
		srtt:   100 * msNano,
		rttvar: 20 * msNano,
	}
	conn := Connection{RTT: *rtt}

	// Update RTT with same measurement
	measurement := uint64(100 * msNano)
	conn.UpdateRTT(measurement)

	// Expected values - RTT should remain the same
	expectedRTT := uint64(100 * msNano)
	// 3/4 * 20ms + 1/4 * 0ms = 15ms
	expectedVar := uint64(15 * msNano)

	assert.Equal(t, expectedRTT, conn.srtt, "RTT should match expected value")
	assert.Equal(t, expectedVar, conn.rttvar, "RTT variance should match expected value")
}

// TestHighVarianceRTT tests with high variance in measurements
func TestHighVarianceRTT(t *testing.T) {
	// Create a new connection
	rtt := &RTT{
		srtt:   100 * msNano,
		rttvar: 50 * msNano,
	}
	conn := Connection{RTT: *rtt}

	// Update RTT with much higher measurement
	measurement := uint64(300 * msNano)
	conn.UpdateRTT(measurement)

	// Expected values - 7/8 * 100ms + 1/8 * 300ms = 125ms
	expectedRTT := uint64(125 * msNano)
	// 3/4 * 50ms + 1/4 * 200ms = 87.5ms
	expectedVar := uint64(87500 * 1000)

	assert.Equal(t, expectedRTT, conn.srtt, "RTT should match expected value")
	assert.Equal(t, expectedVar, conn.rttvar, "RTT variance should match expected value")
}

// TestRTOCalculationDefault tests the RTO calculation with default values
func TestRTOCalculationDefault(t *testing.T) {
	rtt := &RTT{
		srtt:   0,
		rttvar: 0,
	}
	conn := Connection{RTT: *rtt}

	// For new connection with no RTT measurements
	rto := conn.rtoNano()
	expectedRTO := uint64(200 * msNano) // Default of 200ms

	assert.Equal(t, expectedRTO, rto, "Default RTO should be 200ms")
}

// TestRTOCalculationStandardNetwork tests RTO with standard network conditions
func TestRTOCalculationStandardNetwork(t *testing.T) {
	rtt := &RTT{
		srtt:   100 * msNano, // 100ms
		rttvar: 25 * msNano,  // 25ms
	}
	conn := Connection{RTT: *rtt}

	rto := conn.rtoNano()
	// 100ms + 4 * 25ms = 200ms
	expectedRTO := uint64(200 * msNano)

	assert.Equal(t, expectedRTO, rto, "RTO should be 200ms for standard network")
}

// TestRTOCalculationHighLatency tests RTO with high latency network
func TestRTOCalculationHighLatency(t *testing.T) {
	rtt := &RTT{
		srtt:   500 * msNano, // 500ms
		rttvar: 100 * msNano, // 100ms
	}
	conn := Connection{RTT: *rtt}

	rto := conn.rtoNano()
	// 500ms + 4 * 100ms = 900ms
	expectedRTO := uint64(900 * msNano)

	assert.Equal(t, expectedRTO, rto, "RTO should be 900ms for high latency network")
}

// TestRTOCalculationVeryHighLatency tests RTO with very high latency
func TestRTOCalculationVeryHighLatency(t *testing.T) {
	rtt := &RTT{
		srtt:   1500 * msNano, // 1.5s
		rttvar: 200 * msNano,  // 200ms
	}
	conn := Connection{RTT: *rtt}

	rto := conn.rtoNano()
	// 1500ms + 4 * 200ms = 2300ms, capped at 2000ms
	expectedRTO := uint64(2000 * msNano)

	assert.Equal(t, expectedRTO, rto, "RTO should be capped at 2s for very high latency")
}

// TestRTOCalculationExtremeLatency tests RTO with extreme latency (exceeds max)
func TestRTOCalculationExtremeLatency(t *testing.T) {
	rtt := &RTT{
		srtt:   3000 * msNano, // 3s
		rttvar: 500 * msNano,  // 500ms
	}
	conn := Connection{RTT: *rtt}

	rto := conn.rtoNano()
	// Should be capped at maximum
	expectedRTO := uint64(2000 * msNano) // 2s maximum

	assert.Equal(t, expectedRTO, rto, "RTO should be capped at 2s for extreme latency")
}

// TestBackoffFirstRetry tests the first retry with no actual backoff
func TestBackoffFirstRetry(t *testing.T) {
	baseRTO := uint64(200 * msNano) // 200ms
	backoffRTO, err := backoff(baseRTO, 1)

	assert.NoError(t, err)
	assert.Equal(t, uint64(200*msNano), backoffRTO, "First retry should equal base RTO")
}

// TestBackoffSecondRetry tests the second retry with 2x backoff
func TestBackoffSecondRetry(t *testing.T) {
	baseRTO := uint64(200 * msNano) // 200ms
	backoffRTO, err := backoff(baseRTO, 2)

	assert.NoError(t, err)
	assert.Equal(t, uint64(400*msNano), backoffRTO, "Second retry should be 2x base RTO")
}

// TestBackoffThirdRetry tests the third retry with 4x backoff
func TestBackoffThirdRetry(t *testing.T) {
	baseRTO := uint64(200 * msNano) // 200ms
	backoffRTO, err := backoff(baseRTO, 3)

	assert.NoError(t, err)
	assert.Equal(t, uint64(800*msNano), backoffRTO, "Third retry should be 4x base RTO")
}

// TestBackoffFourthRetry tests the fourth retry with 8x backoff
func TestBackoffFourthRetry(t *testing.T) {
	baseRTO := uint64(200 * msNano) // 200ms
	backoffRTO, err := backoff(baseRTO, 4)

	assert.NoError(t, err)
	assert.Equal(t, uint64(1600*msNano), backoffRTO, "Fourth retry should be 8x base RTO")
}

// TestBackoffFifthRetry tests the fifth retry with 16x backoff
func TestBackoffFifthRetry(t *testing.T) {
	baseRTO := uint64(200 * msNano) // 200ms
	backoffRTO, err := backoff(baseRTO, 5)

	assert.NoError(t, err)
	assert.Equal(t, uint64(3200*msNano), backoffRTO, "Fifth retry should be 16x base RTO")
}

// TestBackoffExceedsMaximum tests exceeding the maximum retry count
func TestBackoffExceedsMaximum(t *testing.T) {
	baseRTO := uint64(200 * msNano) // 200ms
	_, err := backoff(baseRTO, 6)

	assert.Error(t, err, "Should error when exceeding max retry attempts")
	assert.Equal(t, "max retry attempts (4) exceeded", err.Error())
}

// TestBackoffInvalidRetryNumber tests with an invalid retry number
func TestBackoffInvalidRetryNumber(t *testing.T) {
	baseRTO := uint64(200 * msNano) // 200ms
	_, err := backoff(baseRTO, 0)

	assert.Error(t, err, "Should error with invalid retry number")
	assert.Equal(t, "backoff requires a positive rto number", err.Error())
}

// TestBackoffWithDifferentBaseRTO tests backoff with a different base RTO
func TestBackoffWithDifferentBaseRTO(t *testing.T) {
	baseRTO := uint64(150 * msNano) // 150ms
	backoffRTO, err := backoff(baseRTO, 2)

	assert.NoError(t, err)
	assert.Equal(t, uint64(300*msNano), backoffRTO, "Should be 2x the base RTO of 150ms")
}
