package interceptor

import "time"

type CallRecord struct {
	Type      string
	Path      string
	FD        int32
	DataSize  int
	Addr      string
	Port      uint16
	ClockID   uint32
	Args      []string
	Decision  PolicyDecision
	Timestamp time.Time
}
