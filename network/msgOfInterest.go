// Copyright (C) 2019-2021 Algorand, Inc.
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
	for _, tag := range strings.Split(string(tags), topicsEncodingSeparator) {
		msgTagsMap[protocol.Tag(tag)] = true
	}
	return msgTagsMap, nil
}

// MarshallMessageOfInterest generate a message of interest message body for a given set of message tags.
func MarshallMessageOfInterest(messageTags []protocol.Tag) []byte {
	// create a long string with all these messages.
	tags := ""
	for _, tag := range messageTags {
		tags += topicsEncodingSeparator + string(tag)
	}
	if len(tags) > 0 {
		tags = tags[len(topicsEncodingSeparator):]
	}
	topics := Topics{Topic{key: "tags", data: []byte(tags)}}
	return topics.MarshallTopics()
}

// MarshallMessageOfInterestMap generates a message of interest message body
// for the message tags that map to "true" in the map argument.
func MarshallMessageOfInterestMap(tagmap map[protocol.Tag]bool) []byte {
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
