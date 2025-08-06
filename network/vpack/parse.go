// Copyright (C) 2019-2025 Algorand, Inc.
// This file is part of go-algorand
//
// go-algorand is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// go-algorand is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-algorand.  If not, see <https://www.gnu.org/licenses/>.

package vpack

import (
	"fmt"
)

type voteValueType uint8

const (
	credPfVoteValue voteValueType = iota
	rPerVoteValue
	rPropDigVoteValue
	rPropEncdigVoteValue
	rPropOperVoteValue
	rPropOpropVoteValue
	rRndVoteValue
	rSndVoteValue
	rStepVoteValue
	sigP1sVoteValue
	sigP2VoteValue
	sigP2sVoteValue
	sigPVoteValue
	sigPsVoteValue
	sigSVoteValue
)

func parseMsgpVote(msgpData []byte, c *StatelessEncoder) error {
	p := newMsgpVoteParser(msgpData)

	// Parse unauthenticatedVote
	cnt, err := p.readFixMap()
	if err != nil {
		return fmt.Errorf("reading map for unauthenticatedVote: %w", err)
	}
	// Assert unauthenticatedVote struct has 3 fields
	if cnt != 3 {
		return fmt.Errorf("expected fixed map size 3 for unauthenticatedVote, got %d", cnt)
	}
	// Required nested map in unauthenticatedVote: cred
	if s, rErr := p.readString(); rErr != nil || string(s) != "cred" {
		return fmt.Errorf("expected string cred, got %s: %w", s, rErr)
	}

	// Parse UnauthenticatedCredential
	cnt, err = p.readFixMap()
	if err != nil {
		return fmt.Errorf("reading map for UnauthenticatedCredential: %w", err)
	}
	// Assert UnauthenticatedCredential struct has 1 fields
	if cnt != 1 {
		return fmt.Errorf("expected fixed map size 1 for UnauthenticatedCredential, got %d", cnt)
	}
	// Required field name for UnauthenticatedCredential: pf
	if s, rErr := p.readString(); rErr != nil || string(s) != "pf" {
		return fmt.Errorf("expected string pf, got %s: %w", s, rErr)
	}
	val, err := p.readBin80()
	if err != nil {
		return fmt.Errorf("reading pf: %w", err)
	}
	c.writeBin80(credPfVoteValue, val)

	// Required nested map in unauthenticatedVote: r
	if s, rErr := p.readString(); rErr != nil || string(s) != "r" {
		return fmt.Errorf("expected string r, got %s: %w", s, rErr)
	}

	// Parse rawVote fixmap
	cnt, err = p.readFixMap()
	if err != nil {
		return fmt.Errorf("reading map for rawVote: %w", err)
	}
	if cnt < 1 || cnt > 5 {
		return fmt.Errorf("expected fixmap size for rawVote 1 <= cnt <= 5, got %d", cnt)
	}
	for range cnt {
		voteKey, err1 := p.readString()
		if err1 != nil {
			return fmt.Errorf("reading key for rawVote: %w", err1)
		}
		switch string(voteKey) {
		case "per":
			val, err1 := p.readUintBytes()
			if err1 != nil {
				return fmt.Errorf("reading per: %w", err1)
			}
			c.writeVaruint(rPerVoteValue, val)
		case "prop":
			// Parse proposalValue fixmap
			propCnt, err1 := p.readFixMap()
			if err1 != nil {
				return fmt.Errorf("reading map for proposalValue: %w", err1)
			}
			if propCnt < 1 || propCnt > 4 {
				return fmt.Errorf("expected fixmap size for proposalValue 1 <= cnt <= 4, got %d", propCnt)
			}
			for range propCnt {
				propKey, err2 := p.readString()
				if err2 != nil {
					return fmt.Errorf("reading key for proposalValue: %w", err2)
				}
				switch string(propKey) {
				case "dig":
					val, err2 := p.readBin32()
					if err2 != nil {
						return fmt.Errorf("reading dig: %w", err2)
					}
					c.writeBin32(rPropDigVoteValue, val)

				case "encdig":
					val, err2 := p.readBin32()
					if err2 != nil {
						return fmt.Errorf("reading encdig: %w", err2)
					}
					c.writeBin32(rPropEncdigVoteValue, val)

				case "oper":
					val, err2 := p.readUintBytes()
					if err2 != nil {
						return fmt.Errorf("reading oper: %w", err2)
					}
					c.writeVaruint(rPropOperVoteValue, val)
				case "oprop":
					val, err2 := p.readBin32()
					if err2 != nil {
						return fmt.Errorf("reading oprop: %w", err2)
					}
					c.writeBin32(rPropOpropVoteValue, val)

				default:
					return fmt.Errorf("unexpected field in proposalValue: %q", propKey)
				}
			}
		case "rnd":
			val, err1 := p.readUintBytes()
			if err1 != nil {
				return fmt.Errorf("reading rnd: %w", err1)
			}
			c.writeVaruint(rRndVoteValue, val)
		case "snd":
			val, err1 := p.readBin32()
			if err1 != nil {
				return fmt.Errorf("reading snd: %w", err1)
			}
			c.writeBin32(rSndVoteValue, val)

		case "step":
			val, err1 := p.readUintBytes()
			if err1 != nil {
				return fmt.Errorf("reading step: %w", err1)
			}
			c.writeVaruint(rStepVoteValue, val)
		default:
			return fmt.Errorf("unexpected field in rawVote: %q", voteKey)
		}
	}

	// Required nested map in unauthenticatedVote: sig
	if s, rErr := p.readString(); rErr != nil || string(s) != "sig" {
		return fmt.Errorf("expected string sig, got %s: %w", s, rErr)
	}

	// Parse OneTimeSignature fixmap
	cnt, err = p.readFixMap()
	if err != nil {
		return fmt.Errorf("reading map for OneTimeSignature: %w", err)
	}
	// Assert OneTimeSignature struct has 6 fields
	if cnt != 6 {
		return fmt.Errorf("expected fixed map size 6 for OneTimeSignature, got %d", cnt)
	}
	// Required field for OneTimeSignature: p
	if s, rErr := p.readString(); rErr != nil || string(s) != "p" {
		return fmt.Errorf("expected string p, got %s: %w", s, rErr)
	}
	val32, err := p.readBin32()
	if err != nil {
		return fmt.Errorf("reading p: %w", err)
	}
	c.writeBin32(sigPVoteValue, val32)

	// Required field for OneTimeSignature: p1s
	if s, rErr := p.readString(); rErr != nil || string(s) != "p1s" {
		return fmt.Errorf("expected string p1s, got %s: %w", s, rErr)
	}
	val64, err := p.readBin64()
	if err != nil {
		return fmt.Errorf("reading p1s: %w", err)
	}
	c.writeBin64(sigP1sVoteValue, val64)

	// Required field for OneTimeSignature: p2
	if s, rErr := p.readString(); rErr != nil || string(s) != "p2" {
		return fmt.Errorf("expected string p2, got %s: %w", s, rErr)
	}
	val32, err = p.readBin32()
	if err != nil {
		return fmt.Errorf("reading p2: %w", err)
	}
	c.writeBin32(sigP2VoteValue, val32)

	// Required field for OneTimeSignature: p2s
	if s, rErr := p.readString(); rErr != nil || string(s) != "p2s" {
		return fmt.Errorf("expected string p2s, got %s: %w", s, rErr)
	}
	val64, err = p.readBin64()
	if err != nil {
		return fmt.Errorf("reading p2s: %w", err)
	}
	c.writeBin64(sigP2sVoteValue, val64)

	// Required field for OneTimeSignature: ps
	if s, rErr := p.readString(); rErr != nil || string(s) != "ps" {
		return fmt.Errorf("expected string ps, got %s: %w", s, rErr)
	}
	val64, err = p.readBin64()
	if err != nil {
		return fmt.Errorf("reading ps: %w", err)
	}
	if val64 != [64]byte{} {
		return fmt.Errorf("expected empty array for ps, got %v", val64)
	}

	// Required field for OneTimeSignature: s
	if s, rErr := p.readString(); rErr != nil || string(s) != "s" {
		return fmt.Errorf("expected string s, got %s: %w", s, rErr)
	}
	val64, err = p.readBin64()
	if err != nil {
		return fmt.Errorf("reading s: %w", err)
	}
	c.writeBin64(sigSVoteValue, val64)

	// Check for trailing bytes
	if p.pos < len(p.data) {
		return fmt.Errorf("unexpected trailing data: %d bytes remain unprocessed", len(p.data)-p.pos)
	}
	return nil
}
