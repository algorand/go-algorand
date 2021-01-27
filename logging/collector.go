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

package logging

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/algorand/go-algorand/util/s3"
)

// CollectAndUploadData combines all of the data files that we want packaged up and uploaded
// for analysis and uploads the tarball to S3.
// dataDir: the node's data directory containing the files of interest
// bundleFilename: the name of the resulting tarball on S3
// targetFolder: the subfolder in the s3 bucket to store the file
func CollectAndUploadData(dataDir string, bundleFilename string, targetFolder string) <-chan error {
	errorChannel := make(chan error, 1)
	pipeReader, pipeWriter := io.Pipe()
	go func() {
		// Close the error channel to signal completion
		defer close(errorChannel)

		bucket := s3.GetS3UploadBucket()
		s3Session, err := s3.MakeS3SessionForUploadWithBucket(bucket)
		if err != nil {
			errorChannel <- err
			return
		}
		wg := sync.WaitGroup{}
		wg.Add(1)
		targetFilename := filepath.Join(targetFolder, path.Base(bundleFilename))
		go func() {
			fmt.Printf("Uploading to s3://%s/%s\n", bucket, targetFilename)
			err = s3Session.UploadFileStream(targetFilename, pipeReader)
			if err != nil {
				errorChannel <- err
			}
			pipeReader.Close()
			wg.Done()
		}()

		err = collectAndWrite(dataDir, pipeWriter)
		if err != nil {
			errorChannel <- err
		}
		// Close writer (our source) so reader knows there's no more data
		pipeWriter.Close()
		// Now wait for reader (S3 uploader) to finish uploading
		wg.Wait()
	}()
	return errorChannel
}

func collectAndWrite(datadir string, writer io.Writer) error {
	// set up the gzip writer
	gw := gzip.NewWriter(writer)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	logPaths, err := filepath.Glob(path.Join(datadir, "node*.log"))
	if err != nil {
		return err
	}
	paths := make([]string, 0)
	paths = append(paths, logPaths...)

	logPaths, err = filepath.Glob(path.Join(datadir, "algod-*.log"))
	if err != nil {
		return err
	}
	paths = append(paths, logPaths...)

	logPaths, err = filepath.Glob(path.Join(datadir, "host*.log"))
	if err != nil {
		return err
	}
	paths = append(paths, logPaths...)

	cadaverPaths, err := filepath.Glob(path.Join(datadir, "agreement.cdv*"))
	if err != nil {
		return err
	}
	paths = append(paths, cadaverPaths...)

	// add each file as needed into the current tar archive
	for i := range paths {
		if err := addFile(tw, paths[i]); err != nil {
			return err
		}
	}
	return nil
}

func addFile(tw *tar.Writer, filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	if stat, err := file.Stat(); err == nil {
		// now create the header as needed for this file within the tarball
		header := new(tar.Header)
		_, header.Name = filepath.Split(filePath)
		header.Size = stat.Size()
		header.Mode = int64(stat.Mode())
		header.ModTime = stat.ModTime()
		// write the header to the tarball archive
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		// copy the file data to the tarball
		if _, err := io.Copy(tw, file); err != nil {
			return err
		}
	}
	return nil
}
