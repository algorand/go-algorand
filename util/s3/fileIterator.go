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

package s3

import (
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

type fileIterator struct {
	filePaths []string
	bucket    string
	subFolder string
	next      struct {
		path string
		f    *os.File
	}
	err error
}

func makeFileIterator(files []string, bucket string, targetFolder string) s3manager.BatchUploadIterator {
	return &fileIterator{
		filePaths: files,
		bucket:    bucket,
		subFolder: targetFolder,
	}
}

func (iter *fileIterator) Next() bool {
	if len(iter.filePaths) == 0 {
		iter.next.f = nil
		return false
	}

	f, err := os.Open(iter.filePaths[0])
	iter.err = err

	iter.next.f = f
	iter.next.path = filepath.Join(iter.subFolder, filepath.Base(iter.filePaths[0]))

	iter.filePaths = iter.filePaths[1:]
	return iter.Err() == nil
}

// Err returns an error that was set during opening the file
func (iter *fileIterator) Err() error {
	return iter.err
}

// UploadObject returns a BatchUploadObject and sets the After field to
// close the file.
func (iter *fileIterator) UploadObject() s3manager.BatchUploadObject {
	f := iter.next.f
	return s3manager.BatchUploadObject{
		Object: &s3manager.UploadInput{
			Bucket: &iter.bucket,
			Key:    &iter.next.path,
			Body:   f,
		},
		// After was introduced in version 1.10.7
		After: func() error {
			return f.Close()
		},
	}
}
