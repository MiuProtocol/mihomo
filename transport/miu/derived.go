package miu

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// derivedPaddingReader consumes the deterministic bytes used to generate a
// per-PSK padding profile. Runtime record sizes are still picked at random in
// paddingScheme.sizesFor; this reader only chooses the profile structure.
type derivedPaddingReader struct {
	prk     []byte
	block   []byte
	pos     int
	counter uint32
}

// golang.org/x/crypto/hkdf rather than crypto/hkdf: the latter only exists from Go 1.24 on, and this
// package builds with Go 1.20.
func newDerivedPaddingReader(authToken [32]byte) (*derivedPaddingReader, error) {
	r := &derivedPaddingReader{prk: hkdf.Extract(sha256.New, authToken[:], []byte(derivedProfileSalt))}
	if err := r.expand(derivedProfileInfo); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *derivedPaddingReader) expand(info string) error {
	block := make([]byte, derivedProfileBlock)
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, r.prk, []byte(info)), block); err != nil {
		return err
	}
	r.block, r.pos = block, 0
	return nil
}

func (r *derivedPaddingReader) refill() error {
	r.counter++
	return r.expand(derivedProfileInfo + "/counter/" + strconv.FormatUint(uint64(r.counter), 10))
}

func (r *derivedPaddingReader) uint16() (uint16, error) {
	if r.pos+2 > len(r.block) {
		if err := r.refill(); err != nil {
			return 0, err
		}
	}
	x := binary.BigEndian.Uint16(r.block[r.pos : r.pos+2])
	r.pos += 2
	return x, nil
}

// sample returns an unbiased value in [lo, hi). It uses rejection sampling
// over uint16 values, so the generated scheme is independent of modulo bias.
func (r *derivedPaddingReader) sample(lo, hi int) (int, error) {
	if lo >= hi {
		return 0, fmt.Errorf("miu: invalid derived range %d-%d", lo, hi)
	}
	span := hi - lo
	limit := 1<<16 - (1<<16)%span
	for {
		x, err := r.uint16()
		if err != nil {
			return 0, err
		}
		if int(x) < limit {
			return lo + int(x)%span, nil
		}
	}
}

func (r *derivedPaddingReader) bit() (bool, error) {
	x, err := r.sample(0, 2)
	return x == 1, err
}

// derivePaddingScheme deterministically creates the v1 profile from the
// existing authentication token. It is deliberately separate from auth: the
// token remains the wire authentication value and this profile is only a
// shaping policy.
func derivePaddingScheme(authToken [32]byte) (*paddingScheme, error) {
	r, err := newDerivedPaddingReader(authToken)
	if err != nil {
		return nil, err
	}
	count, err := r.sample(4, 10)
	if err != nil {
		return nil, err
	}
	authLo, err := r.sample(24, 41)
	if err != nil {
		return nil, err
	}
	authHi, err := r.sample(authLo+16, 65)
	if err != nil {
		return nil, err
	}
	capPerPacket := (derivedProfileBudget - authHi) / count
	lines := []string{fmt.Sprintf("stop=%d", count+1), fmt.Sprintf("0=%d-%d", authLo, authHi)}
	upperBound := authHi
	for pkt := 1; pkt <= count; pkt++ {
		double := false
		if capPerPacket >= 384 {
			var err error
			double, err = r.bit()
			if err != nil {
				return nil, err
			}
		}
		if double {
			partCap := capPerPacket / 2
			lo1, hi1, err := derivedRange(r, partCap, 8)
			if err != nil {
				return nil, err
			}
			lo2, hi2, err := derivedRange(r, partCap, 8)
			if err != nil {
				return nil, err
			}
			lines = append(lines, fmt.Sprintf("%d=%d-%d,c,%d-%d", pkt, lo1, hi1, lo2, hi2))
			upperBound += hi1 + hi2
		} else {
			lo, hi, err := derivedRange(r, capPerPacket, 16)
			if err != nil {
				return nil, err
			}
			lines = append(lines, fmt.Sprintf("%d=%d-%d", pkt, lo, hi))
			upperBound += hi
		}
	}
	if upperBound > derivedProfileBudget {
		return nil, fmt.Errorf("miu: derived profile budget exceeded: %d", upperBound)
	}
	text := strings.Join(lines, "\n")
	p := parsePaddingScheme(text)
	if p == nil {
		return nil, fmt.Errorf("miu: generated invalid padding scheme")
	}
	return p, nil
}

func derivedRange(r *derivedPaddingReader, capPerPacket, minWidth int) (int, int, error) {
	lo, err := r.sample(128, capPerPacket-(2*minWidth-1))
	if err != nil {
		return 0, 0, err
	}
	// hi is an exclusive bound in the scheme grammar. Keep at least minWidth
	// values available while never exceeding this packet's conservative cap.
	hi, err := r.sample(lo+minWidth, capPerPacket+1)
	if err != nil {
		return 0, 0, err
	}
	return lo, hi, nil
}
