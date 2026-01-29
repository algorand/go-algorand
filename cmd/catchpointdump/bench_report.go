// Copyright (C) 2019-2026 Algorand, Inc.
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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/algorand/go-algorand/util"
	"github.com/google/uuid"
	"github.com/klauspost/cpuid/v2"
)

type benchStage struct {
	stage     string
	start     time.Time
	duration  time.Duration
	cpuTimeNS int64
	completed bool
}

type hostInfo struct {
	CPUCoreCnt    int       `json:"cores"`
	CPULogicalCnt int       `json:"log_cores"`
	CPUBaseMHz    int64     `json:"base_mhz"`
	CPUMaxMHz     int64     `json:"max_mhz"`
	CPUName       string    `json:"cpu_name"`
	CPUVendor     string    `json:"cpu_vendor"`
	MemMB         int       `json:"mem_mb"`
	OS            string    `json:"os"`
	ID            uuid.UUID `json:"uuid"`
}

type benchReport struct {
	ReportID uuid.UUID     `json:"report"`
	Stages   []*benchStage `json:"stages"`
	HostInfo *hostInfo     `json:"host"`
	// TODO: query cpu cores, bogomips and stuff (windows/mac compatible)
}

func (bs *benchStage) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Stage    string `json:"stage"`
		Duration int64  `json:"duration_sec"`
		CPUTime  int64  `json:"cpu_time_sec"`
	}{
		Stage:    bs.stage,
		Duration: int64(bs.duration.Seconds()),
		CPUTime:  bs.cpuTimeNS / 1000000000,
	})
}

func (bs *benchStage) String() string {
	return fmt.Sprintf(">> stage:%s duration_sec:%.1f duration_min:%.1f cpu_sec:%d", bs.stage, bs.duration.Seconds(), bs.duration.Minutes(), bs.cpuTimeNS/1000000000)
}

func gatherHostInfo() *hostInfo {
	nid := sha256.Sum256(uuid.NodeID())
	uuid, _ := uuid.FromBytes(nid[0:16])

	ni := &hostInfo{
		CPUCoreCnt:    cpuid.CPU.PhysicalCores,
		CPULogicalCnt: cpuid.CPU.LogicalCores,
		CPUName:       cpuid.CPU.BrandName,
		CPUVendor:     cpuid.CPU.VendorID.String(),
		CPUMaxMHz:     cpuid.CPU.BoostFreq / 1_000_000,
		CPUBaseMHz:    cpuid.CPU.Hz / 1_000_000,
		MemMB:         int(util.GetTotalMemory()) / 1024 / 1024,
		ID:            uuid,
		OS:            runtime.GOOS,
	}

	return ni
}

func makeBenchmarkReport() *benchReport {
	uuid, _ := uuid.NewV7()
	return &benchReport{
		Stages:   make([]*benchStage, 0),
		HostInfo: gatherHostInfo(),
		ReportID: uuid,
	}
}

func (br *benchReport) startStage(stage string) *benchStage {
	utime, stime, _ := util.GetCurrentProcessTimes()
	bs := &benchStage{
		stage:     stage,
		start:     time.Now(),
		duration:  0,
		cpuTimeNS: utime + stime,
		completed: false,
	}
	br.Stages = append(br.Stages, bs)
	return bs
}

func (bs *benchStage) completeStage() {
	utime, stime, _ := util.GetCurrentProcessTimes()
	bs.duration = time.Since(bs.start)
	bs.completed = true
	bs.cpuTimeNS = utime + stime - bs.cpuTimeNS
}

func (br *benchReport) printReport() {
	fmt.Print("\nBenchmark report:\n")
	for i := range br.Stages {
		fmt.Println(br.Stages[i].String())
	}
}

func (br *benchReport) saveReport(filename string) error {
	jsonData, err := json.MarshalIndent(br, "", "    ")
	if err != nil {
		return err
	}

	// Write to file with permissions set to 0644
	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		return err
	}

	return nil
}
