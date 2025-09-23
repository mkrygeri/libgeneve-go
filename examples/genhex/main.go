package main

import (
	"encoding/hex"
	"fmt"

	"github.com/mkrygeri/libgeneve-go/geneve"
)

func main() {
	// Create packet with INT metadata
	intOpt := geneve.INTMetadataOption{
		Version:           4,
		Discard:           true,
		RemainingHopCount: 10,
		InstructionBitmap: geneve.INTInstrSwitchID | geneve.INTInstrHopLatency,
		DomainSpecificID:  0x1234,
	}

	packet := geneve.NewPacketBuilder().
		SetVNI(0x123456).
		AddINTMetadataOption(intOpt).
		SetPayload([]byte("Hello INT")).
		Build()

	fmt.Print(hex.EncodeToString(packet))
}