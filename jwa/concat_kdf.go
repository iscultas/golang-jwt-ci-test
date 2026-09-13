package jwa

import (
	"crypto"
	"encoding/binary"
)

func concatKDF(sharedSecret []byte, algorithmID string, partyUInfo, partyVInfo []byte, size int) []byte {
	hash := crypto.SHA256.New()

	otherInfo := lengthPrefixed([]byte(algorithmID))
	otherInfo = append(otherInfo, lengthPrefixed(partyUInfo)...)
	otherInfo = append(otherInfo, lengthPrefixed(partyVInfo)...)

	//nolint:gosec // size is a key length in octets, which this package sets from the algorithm and never from a token.
	otherInfo = binary.BigEndian.AppendUint32(otherInfo, uint32(size)*8)

	derived := make([]byte, 0, size)

	for round := uint32(1); len(derived) < size; round++ {
		hash.Reset()
		hash.Write(binary.BigEndian.AppendUint32(nil, round))
		hash.Write(sharedSecret)
		hash.Write(otherInfo)

		derived = hash.Sum(derived)
	}

	return derived[:size]
}

func lengthPrefixed(data []byte) []byte {
	//nolint:gosec // The length prefix of RFC 7518 section 4.6.2, over a value this package assembles.
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(data))), data...)
}
