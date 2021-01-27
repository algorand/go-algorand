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

package component

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/algorand/go-algorand/libgoal"
	"github.com/algorand/go-algorand/shared/pingpong"
)

// PingPongComponentInstance extends component instance
// supports management of ping pong instances
type PingPongComponentInstance struct {
	ci         Instance
	ctx        context.Context
	cancelFunc context.CancelFunc
}

func getPingPongConfig(command Command) (config pingpong.PpConfig, err error) {
	err = json.Unmarshal([]byte(command.options), &config)
	return
}

// Init the PingPong instance
func (componentInstance *PingPongComponentInstance) Init() (err error) {
	return
}

// Process the ping pong instance
func (componentInstance *PingPongComponentInstance) Process(command Command) (err error) {

	switch command.command {
	case "start":
		// terminate previous instance
		err = componentInstance.Terminate()
		if err != nil {
			log.Warnf("terminating component instance resulted in error: %v", err)
		}

		//  unmarshal config sent by client
		var pingPongConfig pingpong.PpConfig
		pingPongConfig, err = getPingPongConfig(command)
		if err != nil {
			err = fmt.Errorf("error demarshalling ping pong options %s, err: %v", command.options, err)
			log.Errorf("%v", err)
		} else {
			log.Infof("starting Ping Pong with configuration %+v", pingPongConfig)
			err = componentInstance.startPingPong(&pingPongConfig)
			if err != nil {
				err = fmt.Errorf("starting ping pong instance resulted in error: %v", err)
				log.Errorf("%v", err)
			} else {
				log.Infof("ping pong process started")
			}
		}
		break
	case "stop":
		log.Infof("terminating Ping Pong")
		err = componentInstance.Terminate()
		if err != nil {
			err = fmt.Errorf("terminating ping pong instance resulted in error: %v", err)
			log.Errorf("%v", err)
		} else {
			log.Infof("ping pong process terminated")
		}
		break
	default:
		log.Warnf("unsupported pingpong action '%s'", command.command)
	}
	return
}

// Terminate the ping pong instance
func (componentInstance *PingPongComponentInstance) Terminate() (err error) {
	if componentInstance.cancelFunc != nil {
		componentInstance.cancelFunc()
		componentInstance.cancelFunc = nil
		componentInstance.ctx = nil
	}
	return
}

func (componentInstance *PingPongComponentInstance) startPingPong(cfg *pingpong.PpConfig) (err error) {
	// Make a cache dir for wallet handle tokens
	cacheDir, err := ioutil.TempDir(GetHostAgent().TempDir, PINGPONG)
	if err != nil {
		log.Errorf("Cannot make temp dir: %v\n", err)
		return
	}

	ac, err := libgoal.MakeClientWithBinDir(GetHostAgent().BinDir, componentInstance.ci.dataDir, cacheDir, libgoal.FullClient)
	if err != nil {
		log.Errorf("failed to create lib goal client %v", err)
		return
	}

	// Prepare configuration
	if cfg == nil {
		cfg = &pingpong.DefaultConfig
	}

	log.Infof("Preparing to initialize PingPong with config: %+v\n", cfg)

	var accounts map[string]uint64
	var cinfo pingpong.CreatablesInfo
	var resultCfg pingpong.PpConfig

	// Initialize accounts if necessary, this may take several attempts while previous transactions to settle
	for i := 0; i < 10; i++ {
		accounts, cinfo, resultCfg, err = pingpong.PrepareAccounts(ac, *cfg)
		if err == nil {
			break
		} else {
			log.Warnf("problem[%d] preparing accounts for transfers: %v\n, retrying", i, err)
			time.Sleep(time.Second * 2)
		}
	}
	if err != nil {
		log.Errorf("Error preparing accounts for transfers: %v\n", err)
		return
	}

	log.Infof("Preparing to run PingPong with config: %+v\n", cfg)

	// prepare cancelable context
	componentInstance.ctx, componentInstance.cancelFunc = context.WithCancel(context.Background())

	// Kick off the real processing
	go pingpong.RunPingPong(componentInstance.ctx, ac, accounts, cinfo, resultCfg)

	return
}
