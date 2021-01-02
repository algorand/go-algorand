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

package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/algorand/go-algorand/util/s3"
	"github.com/algorand/go-algorand/util/tar"
)

func downloadAndExtractConfigPackage(channel string, targetDir string, configBucket string) (err error) {
	fmt.Fprintf(os.Stdout, "Downloading latest configuration file for '%s'...\n", channel)
	packageFile, err := downloadConfigPackage(channel, targetDir, configBucket)
	if err != nil {
		return fmt.Errorf("error downloading config package for channel '%s': %v", channel, err)
	}

	// Extract package and update configFilename
	fmt.Fprintf(os.Stdout, "Expanding configuration package '%s' to %s\n", packageFile, targetDir)
	return extractConfigPackage(packageFile, targetDir)
}

func downloadConfigPackage(channelName string, targetDir string, configBucket string) (packageFile string, err error) {
	if configBucket == "" {
		configBucket = s3.GetS3ReleaseBucket()
	}
	fmt.Fprintf(os.Stdout, "Downloading configuration package for channel '%s' from bucket '%s'\n", channelName, configBucket)
	s3Session, err := s3.MakeS3SessionForDownloadWithBucket(configBucket)
	if err != nil {
		return
	}

	prefix := fmt.Sprintf("config_%s", channelName)
	version, name, err := s3Session.GetLatestPackageFilesVersion(channelName, prefix)
	if err != nil {
		return
	}
	if version == 0 {
		err = fmt.Errorf("no config package found for channel '%s'", channelName)
		return
	}

	fileName := path.Base(name)
	packageFile = filepath.Join(targetDir, fileName)
	file, err := os.Create(packageFile)
	if err != nil {
		return
	}
	defer file.Close()

	if err = s3Session.DownloadFile(name, file); err != nil {
		err = fmt.Errorf("error downloading file: %v", err)
		return
	}
	return
}

func extractConfigPackage(packageFile string, targetDir string) (err error) {
	err = tar.UncompressFile(packageFile, targetDir)
	if err != nil {
		return
	}
	return
}
