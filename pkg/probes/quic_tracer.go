package probes

import (
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go/logging"

	"github.com/mt-inside/print-cert/pkg/state"

	"github.com/mt-inside/http-log/pkg/bios"
	"github.com/mt-inside/http-log/pkg/output"
)

func newTracer(
	s output.TtyStyler,
	b bios.Bios,
	pD *state.ResponseData,
) *logging.ConnectionTracer {
	return &logging.ConnectionTracer{
		StartedConnection: func(local, remote net.Addr, srcConnID, destConnID logging.ConnectionID) {
			pD.StartTime = time.Now() // start and connection times are an even worse concept with lazy connections like this
			log.Info("Dialing", "net", "udp", "addr", remote)
			pD.TransportConnTime = time.Now()
			log.Info("Connected", "to", remote, "from", local)

			pD.TransportLocalAddr = local
			pD.TransportRemoteAddr = remote
		},

		NegotiatedVersion: func(chosen logging.VersionNumber, clientVersions, serverVersions []logging.VersionNumber) {
			pD.TransportVersion = chosen
		},
		ClosedConnection: func(err error) {
			// Don't believe the connection will currently close as they're persistent; we just quit
			fmt.Printf("Closed (err only?) %v\n", err)
		},
		SentTransportParameters: func(*logging.TransportParameters) {
		},
		ReceivedTransportParameters: func(*logging.TransportParameters) {
		},
		RestoredTransportParameters: func(parameters *logging.TransportParameters) {
		},
		SentLongHeaderPacket: func(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, ack *logging.AckFrame, frames []logging.Frame) {
		},
		SentShortHeaderPacket: func(hdr *logging.ShortHeader, size logging.ByteCount, ecn logging.ECN, ack *logging.AckFrame, frames []logging.Frame) {
		},
		ReceivedVersionNegotiationPacket: func(dest, src logging.ArbitraryLenConnectionID, _ []logging.VersionNumber) {
		},
		ReceivedRetry: func(*logging.Header) {
		},
		ReceivedLongHeaderPacket: func(hdr *logging.ExtendedHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
		},
		ReceivedShortHeaderPacket: func(hdr *logging.ShortHeader, size logging.ByteCount, ecn logging.ECN, frames []logging.Frame) {
		},
		BufferedPacket: func(logging.PacketType, logging.ByteCount) {
		},
		DroppedPacket: func(logging.PacketType, logging.PacketNumber, logging.ByteCount, logging.PacketDropReason) {
		},
		UpdatedMetrics: func(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) {
		},
		AcknowledgedPacket: func(logging.EncryptionLevel, logging.PacketNumber) {
		},
		LostPacket: func(logging.EncryptionLevel, logging.PacketNumber, logging.PacketLossReason) {
		},
		UpdatedCongestionState: func(logging.CongestionState) {
		},
		UpdatedPTOCount: func(value uint32) {
		},
		UpdatedKeyFromTLS: func(logging.EncryptionLevel, logging.Perspective) {
		},
		UpdatedKey: func(generation logging.KeyPhase, remote bool) {
		},
		DroppedEncryptionLevel: func(logging.EncryptionLevel) {
		},
		DroppedKey: func(generation logging.KeyPhase) {
		},
		SetLossTimer: func(logging.TimerType, logging.EncryptionLevel, time.Time) {
		},
		LossTimerExpired: func(logging.TimerType, logging.EncryptionLevel) {
		},
		LossTimerCanceled: func() {
		},
		Close: func() {
			// Don't believe the connection will currently close as they're persistent; we just quit
			fmt.Println("Close")
		},
		Debug: func(name, msg string) {
		},
	}
}
