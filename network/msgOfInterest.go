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

package network

import (
	"errors"
	"strings"

	"github.com/algorand/go-algorand/protocol"
)

var errUnableUnmarshallMessage = errors.New("unmarshalMessageOfInterest: could not unmarshall message")
var errInvalidMessageOfInterest = errors.New("unmarshalMessageOfInterest: message missing the tags key")
var errInvalidMessageOfInterestLength = errors.New("unmarshalMessageOfInterest: message length is too long")
var errInvalidMessageOfInterestInvalidTag = errors.New("unmarshalMessageOfInterest: invalid tag")

const maxMessageOfInterestTags = 1024
const topicsEncodingSeparator = ","

func unmarshallMessageOfInterest(data []byte) (map[protocol.Tag]bool, error) {
	// decode the message, and ensure it's a valid message.
	topics, err := UnmarshallTopics(data)
	if err != nil {
		return nil, errUnableUnmarshallMessage
	}
	tags, found := topics.GetValue("tags")
	if !found {
		return nil, errInvalidMessageOfInterest
	}
	if len(tags) > maxMessageOfInterestTags {
		return nil, errInvalidMessageOfInterestLength
	}
	// convert the tags into a tags map.
	msgTagsMap := make(map[protocol.Tag]bool, len(tags))
	for tag := range strings.SplitSeq(string(tags), topicsEncodingSeparator) {
		if len(tag) != protocol.TagLength {
			return nil, errInvalidMessageOfInterestInvalidTag
		}
		if _, ok := protocol.DeprecatedTagMap[protocol.Tag(tag)]; ok {
			continue
		}
		if _, ok := protocol.TagMap[protocol.Tag(tag)]; !ok {
			return nil, errInvalidMessageOfInterestInvalidTag
		}
		msgTagsMap[protocol.Tag(tag)] = true
	}
	return msgTagsMap, nil
}

// marshallMessageOfInterest generates a message of interest message body for a given set of message tags.
func marshallMessageOfInterest(messageTags []protocol.Tag) []byte {
	m := make(map[protocol.Tag]bool)
	for _, tag := range messageTags {
		m[tag] = true
	}
	return marshallMessageOfInterestMap(m)
}

// marshallMessageOfInterestMap generates a message of interest message body
// for the message tags that map to "true" in the map argument.
func marshallMessageOfInterestMap(tagmap map[protocol.Tag]bool) []byte {
	tags := ""
	for tag, flag := range tagmap {
		if flag {
			tags += topicsEncodingSeparator + string(tag)
		}
	}
	if len(tags) > 0 {
		tags = tags[len(topicsEncodingSeparator):]
	}
	topics := Topics{Topic{key: "tags", data: []byte(tags)}}
	return topics.MarshallTopics()
}

// MessageOfInterestMaxSize returns the maximum size of a MI message sent over the network
// by encoding all of the tags currenttly in use.
func MessageOfInterestMaxSize() int {
	allTags := make(map[protocol.Tag]bool, len(protocol.TagList))
	for _, tag := range protocol.TagList {
		allTags[tag] = true
	}
	for tag := range protocol.DeprecatedTagMap {
		allTags[tag] = true
	}
	return len(marshallMessageOfInterestMap(allTags))
}
