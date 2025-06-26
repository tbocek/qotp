package tomtp

import (
	"github.com/MatusOllah/slogcolor"
	"github.com/fatih/color"
	"log/slog"
	"os"
)

const (
	startMtu          = 1400            // QUIC uses 1200 based on studies done around 2016-2018
	maxMtu            = 9000            // support larger packets
	rcvBufferCapacity = 1 * 1024 * 1024 // 1MB
)

var (
	logger = slog.New(slogcolor.NewHandler(os.Stderr, &slogcolor.Options{
		Level:         slog.LevelDebug,
		TimeFormat:    "15:04:05.000",
		SrcFileMode:   slogcolor.ShortFile,
		SrcFileLength: 16,
		MsgPrefix:     color.HiWhiteString("|"),
		MsgColor:      color.New(color.FgHiWhite),
		MsgLength:     24,
	}))
)

func init() {
	color.NoColor = false
	slog.SetDefault(logger)
}
