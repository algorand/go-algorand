// Copyright (C) 2019-2024 Algorand, Inc.
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

package algod

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof" // net/http/pprof is for registering the pprof URLs with the web server, so http://localhost:8080/debug/pprof/ works.
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/algorand/go-deadlock"

	"github.com/algorand/go-algorand/config"
	apiServer "github.com/algorand/go-algorand/daemon/algod/api/server"
	"github.com/algorand/go-algorand/daemon/algod/api/server/lib"
	"github.com/algorand/go-algorand/data/basics"
	"github.com/algorand/go-algorand/data/bookkeeping"
	"github.com/algorand/go-algorand/logging"
	"github.com/algorand/go-algorand/logging/telemetryspec"
	"github.com/algorand/go-algorand/network/limitlistener"
	"github.com/algorand/go-algorand/node"
	"github.com/algorand/go-algorand/util"
	"github.com/algorand/go-algorand/util/metrics"
	"github.com/algorand/go-algorand/util/tokens"
)

var server http.Server

// maxHeaderBytes must have enough room to hold an api token
const maxHeaderBytes = 4096

// ServerNode is the required methods for any node the server fronts
type ServerNode interface {
	apiServer.APINodeInterface
	ListeningAddress() (string, bool)
	Start()
	Stop()
}

// Server represents an instance of the REST API HTTP server
type Server struct {
	RootPath             string
	Genesis              bookkeeping.Genesis
	pidFile              string
	netFile              string
	netListenFile        string
	log                  logging.Logger
	node                 ServerNode
	metricCollector      *metrics.MetricService
	metricServiceStarted bool
	stopping             chan struct{}
}

// Initialize creates a Node instance with applicable network services
func (s *Server) Initialize(cfg config.Local, phonebookAddresses []string, genesisText string) error {
	// set up node
	s.log = logging.Base()

	lib.GenesisJSONText = genesisText

	liveLog, archive := cfg.ResolveLogPaths(s.RootPath)

	var maxLogAge time.Duration
	var err error
	if cfg.LogArchiveMaxAge != "" {
		maxLogAge, err = time.ParseDuration(cfg.LogArchiveMaxAge)
		if err != nil {
			s.log.Fatalf("invalid config LogArchiveMaxAge: %s", err)
			maxLogAge = 0
		}
	}

	var logWriter io.Writer
	if cfg.LogSizeLimit > 0 {
		fmt.Println("Logging to: ", liveLog)
		logWriter = logging.MakeCyclicFileWriter(liveLog, archive, cfg.LogSizeLimit, maxLogAge)
	} else {
		fmt.Println("Logging to: stdout")
		logWriter = os.Stdout
	}
	s.log.SetOutput(logWriter)
	s.log.SetJSONFormatter()
	s.log.SetLevel(logging.Level(cfg.BaseLoggerDebugLevel))
	setupDeadlockLogger()

	// Check some config parameters.
	if cfg.RestConnectionsSoftLimit > cfg.RestConnectionsHardLimit {
		s.log.Warnf(
			"RestConnectionsSoftLimit %d exceeds RestConnectionsHardLimit %d",
			cfg.RestConnectionsSoftLimit, cfg.RestConnectionsHardLimit)
		cfg.RestConnectionsSoftLimit = cfg.RestConnectionsHardLimit
	}
	if cfg.IncomingConnectionsLimit < 0 {
		return fmt.Errorf(
			"Initialize() IncomingConnectionsLimit %d must be non-negative",
			cfg.IncomingConnectionsLimit)
	}

	// Set large enough soft file descriptors limit.
	var ot basics.OverflowTracker
	fdRequired := ot.Add(cfg.ReservedFDs, cfg.RestConnectionsHardLimit)
	if ot.Overflowed {
		return errors.New(
			"Initialize() overflowed when adding up ReservedFDs and RestConnectionsHardLimit; decrease them")
	}
	err = util.SetFdSoftLimit(fdRequired)
	if err != nil {
		return fmt.Errorf("Initialize() err: %w", err)
	}
	// TODO: remove this after making pebble support official
	// and integrate the value into ReservedFDs config parameter.
	if cfg.StorageEngine == "pebbledb" {
		fdRequired = ot.Add(fdRequired, 1000)
		if ot.Overflowed {
			return errors.New(
				"Initialize() overflowed when adding up fdRequired and 1000 needed for pebbledb")
		}
		err = util.SetFdSoftLimit(fdRequired)
		if err != nil {
			return fmt.Errorf("Initialize() failed to set FD limit for pebbledb backend, err: %w", err)
		}
	}

	if cfg.IsGossipServer() {
		var ot basics.OverflowTracker
		fdRequired = ot.Add(fdRequired, uint64(cfg.IncomingConnectionsLimit))
		if ot.Overflowed {
			return errors.New("Initialize() overflowed when adding up IncomingConnectionsLimit to the existing RLIMIT_NOFILE value; decrease RestConnectionsHardLimit or IncomingConnectionsLimit")
		}
		_, hard, fdErr := util.GetFdLimits()
		if fdErr != nil {
			s.log.Errorf("Failed to get RLIMIT_NOFILE values: %s", fdErr.Error())
		} else {
			maxFDs := fdRequired
			if fdRequired > hard {
				// claim as many descriptors are possible
				maxFDs = hard
				// but try to keep cfg.ReservedFDs untouched by decreasing other limits
				if cfg.AdjustConnectionLimits(fdRequired, hard) {
					s.log.Warnf(
						"Updated connection limits: RestConnectionsSoftLimit=%d, RestConnectionsHardLimit=%d, IncomingConnectionsLimit=%d",
						cfg.RestConnectionsSoftLimit,
						cfg.RestConnectionsHardLimit,
						cfg.IncomingConnectionsLimit,
					)
					if cfg.IncomingConnectionsLimit == 0 {
						return errors.New("Initialize() failed to adjust connection limits")
					}
				}
			}
			fdErr = util.SetFdSoftLimit(maxFDs)
			if fdErr != nil {
				// do not fail but log the error
				s.log.Errorf("Failed to set a new RLIMIT_NOFILE value to %d (max %d): %s", fdRequired, hard, fdErr.Error())
			}
		}
	}

	// configure the deadlock detector library
	switch {
	case cfg.DeadlockDetection > 0:
		// Explicitly enabled deadlock detection
		deadlock.Opts.Disable = false

	case cfg.DeadlockDetection < 0:
		// Explicitly disabled deadlock detection
		deadlock.Opts.Disable = true

	case cfg.DeadlockDetection == 0:
		// Default setting - host app should configure this
		// If host doesn't, the default is Disable = false (so, enabled)
	}
	if !deadlock.Opts.Disable {
		deadlock.Opts.DeadlockTimeout = time.Second * time.Duration(cfg.DeadlockDetectionThreshold)
	}

	// if we have the telemetry enabled, we want to use it's sessionid as part of the
	// collected metrics decorations.
	s.log.Infoln("++++++++++++++++++++++++++++++++++++++++")
	s.log.Infoln("Logging Starting")
	if s.log.GetTelemetryUploadingEnabled() {
		// May or may not be logging to node.log
		s.log.Infof("Telemetry Enabled: %s\n", s.log.GetTelemetryGUID())
		s.log.Infof("Session: %s\n", s.log.GetTelemetrySession())
	} else {
		// May or may not be logging to node.log
		s.log.Infoln("Telemetry Disabled")
	}
	s.log.Infoln("++++++++++++++++++++++++++++++++++++++++")

	metricLabels := map[string]string{}
	if s.log.GetTelemetryEnabled() {
		metricLabels["telemetry_session"] = s.log.GetTelemetrySession()
		if h := s.log.GetTelemetryGUID(); h != "" {
			metricLabels["telemetry_host"] = h
		}
		if i := s.log.GetInstanceName(); i != "" {
			metricLabels["telemetry_instance"] = i
		}
	}
	s.metricCollector = metrics.MakeMetricService(
		&metrics.ServiceConfig{
			NodeExporterListenAddress: cfg.NodeExporterListenAddress,
			Labels:                    metricLabels,
			NodeExporterPath:          cfg.NodeExporterPath,
		})

	var serverNode ServerNode
	if cfg.EnableFollowMode {
		var followerNode *node.AlgorandFollowerNode
		followerNode, err = node.MakeFollower(s.log, s.RootPath, cfg, phonebookAddresses, s.Genesis)
		serverNode = apiServer.FollowerNode{AlgorandFollowerNode: followerNode}
	} else {
		var fullNode *node.AlgorandFullNode
		fullNode, err = node.MakeFull(s.log, s.RootPath, cfg, phonebookAddresses, s.Genesis)
		serverNode = apiServer.APINode{AlgorandFullNode: fullNode}
	}
	if os.IsNotExist(err) {
		return fmt.Errorf("node has not been installed: %s", err)
	}
	if err != nil {
		return fmt.Errorf("couldn't initialize the node: %s", err)
	}
	s.node = serverNode

	// When a caller to logging uses Fatal, we want to stop the node before os.Exit is called.
	logging.RegisterExitHandler(s.Stop)

	return nil
}

// helper handles startup of tcp listener
func makeListener(addr string) (net.Listener, error) {
	var listener net.Listener
	var err error
	if (addr == "127.0.0.1:0") || (addr == ":0") {
		// if port 0 is provided, prefer port 8080 first, then fall back to port 0
		preferredAddr := strings.Replace(addr, ":0", ":8080", -1)
		listener, err = net.Listen("tcp", preferredAddr)
		if err == nil {
			return listener, err
		}
	}
	// err was not nil or :0 was not provided, fall back to originally passed addr
	return net.Listen("tcp", addr)
}

// Start starts a Node instance and its network services
func (s *Server) Start() {
	s.log.Info("Trying to start an Algorand node")
	fmt.Print("Initializing the Algorand node... ")
	s.node.Start()
	s.log.Info("Successfully started an Algorand node.")
	fmt.Println("Success!")

	cfg := s.node.Config()

	if cfg.EnableRuntimeMetrics {
		metrics.DefaultRegistry().Register(metrics.NewRuntimeMetrics())
	}

	if cfg.EnableMetricReporting {
		if err := s.metricCollector.Start(context.Background()); err != nil {
			// log this error
			s.log.Infof("Unable to start metric collection service : %v", err)
		}
		s.metricServiceStarted = true
	}

	var apiToken string
	var err error
	fmt.Printf("API authentication disabled: %v\n", cfg.DisableAPIAuth)
	if !cfg.DisableAPIAuth {
		apiToken, err = tokens.GetAndValidateAPIToken(s.RootPath, tokens.AlgodTokenFilename)
		if err != nil {
			fmt.Printf("APIToken error: %v\n", err)
			os.Exit(1)
		}
	}

	adminAPIToken, err := tokens.GetAndValidateAPIToken(s.RootPath, tokens.AlgodAdminTokenFilename)
	if err != nil {
		fmt.Printf("APIToken error: %v\n", err)
		os.Exit(1)
	}

	s.stopping = make(chan struct{})

	addr := cfg.EndpointAddress
	if addr == "" {
		addr = ":http"
	}

	listener, err := makeListener(addr)
	if err != nil {
		fmt.Printf("Could not start node: %v\n", err)
		os.Exit(1)
	}
	listener = limitlistener.RejectingLimitListener(
		listener, cfg.RestConnectionsHardLimit, s.log)

	addr = listener.Addr().String()
	server = http.Server{
		Addr:           addr,
		ReadTimeout:    time.Duration(cfg.RestReadTimeoutSeconds) * time.Second,
		WriteTimeout:   time.Duration(cfg.RestWriteTimeoutSeconds) * time.Second,
		MaxHeaderBytes: maxHeaderBytes,
	}

	e := apiServer.NewRouter(
		s.log, s.node, s.stopping, apiToken, adminAPIToken, listener,
		cfg.RestConnectionsSoftLimit)

	// Set up files for our PID and our listening address
	// before beginning to listen to prevent 'goal node start'
	// quit earlier than these service files get created
	s.pidFile = filepath.Join(s.RootPath, "algod.pid")
	s.netFile = filepath.Join(s.RootPath, "algod.net")
	err = os.WriteFile(s.pidFile, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644)
	if err != nil {
		fmt.Printf("pidfile error: %v\n", err)
		os.Exit(1)
	}
	err = os.WriteFile(s.netFile, []byte(fmt.Sprintf("%s\n", addr)), 0644)
	if err != nil {
		fmt.Printf("netfile error: %v\n", err)
		os.Exit(1)
	}

	listenAddr, listening := s.node.ListeningAddress()
	if listening {
		s.netListenFile = filepath.Join(s.RootPath, "algod-listen.net")
		err = os.WriteFile(s.netListenFile, []byte(fmt.Sprintf("%s\n", listenAddr)), 0644)
		if err != nil {
			fmt.Printf("netlistenfile error: %v\n", err)
			os.Exit(1)
		}
	}

	errChan := make(chan error, 1)
	go func() {
		err := e.StartServer(&server)
		errChan <- err
	}()

	// Handle signals cleanly
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	signal.Ignore(syscall.SIGHUP)

	fmt.Printf("Node running and accepting RPC requests over HTTP on port %v. Press Ctrl-C to exit\n", addr)
	select {
	case err := <-errChan:
		if err != nil {
			s.log.Warn(err)
		} else {
			s.log.Info("Node exited successfully")
		}
		s.Stop()
	case sig := <-c:
		fmt.Printf("Exiting on %v\n", sig)
		s.Stop()
		os.Exit(0)
	}
}

// Stop initiates a graceful shutdown of the node by shutting down the network server.
func (s *Server) Stop() {
	// close the s.stopping, which would signal the rest api router that any pending commands
	// should be aborted.
	close(s.stopping)

	// Attempt to log a shutdown event before we exit...
	s.log.Event(telemetryspec.ApplicationState, telemetryspec.ShutdownEvent)

	s.node.Stop()

	err := server.Shutdown(context.Background())
	if err != nil {
		s.log.Error(err)
	}

	if s.metricServiceStarted {
		if err := s.metricCollector.Shutdown(); err != nil {
			// log this error
			s.log.Infof("Unable to shutdown metric collection service : %v", err)
		}
		s.metricServiceStarted = false
	}

	s.log.CloseTelemetry()

	os.Remove(s.pidFile)
	os.Remove(s.netFile)
	os.Remove(s.netListenFile)
}
