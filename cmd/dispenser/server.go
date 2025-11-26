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

package main

import (
	_ "embed"
	"html"

	// "bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/algorand/go-algorand/libgoal"
)

var configFile = flag.String("config", "", "JSON configuration file")
var autocertDir = flag.String("autocert", "", "Autocert cache directory")
var listenPort = flag.Int("port", 443, "Port to listen for incoming connections")
var httpsCert = flag.String("cert", "", "https certificate.pem file; mutually exclusive with autocert")
var httpsKey = flag.String("key", "", "https key.pem file; mutually exclusive with autocert")
var configMap map[string]dispenserSiteConfig

var client map[string]libgoal.Client

type recaptchaResponse struct {
	Success     bool      `json:"success"`
	ChallengeTS time.Time `json:"challenge_ts"`
	Hostname    string    `json:"hostname"`
	ErrorCodes  []string  `json:"error-codes"`
}

type dispenserSiteConfig struct {
	RecaptchaSiteKey string `json:"recaptcha_sitekey"`
	RecaptchaSecret  string `json:"recaptcha_secret"`
	Amount           int    `json:"amount"`
	Fee              int    `json:"fee"`
	Source           string `json:"wallet"`
	DataDir          string `json:"data_dir"`
	ExeDir           string `json:"exe_dir"`

	topPage string
}

//go:embed index.html.tpl
var topPageTemplate string

func getConfig(r *http.Request) dispenserSiteConfig {
	return configMap[r.Host]
}

func handler(w http.ResponseWriter, r *http.Request) {
	cfg := getConfig(r)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl, err := template.New("top").Parse(topPageTemplate)
	if err != nil {
		log.Printf("Error parsing top page template: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, cfg)
	if err != nil {
		log.Printf("Error executing template: %v\n", err)
	}
}

func (cfg dispenserSiteConfig) checkRecaptcha(remoteip, response string) (r recaptchaResponse, err error) {
	resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify",
		url.Values{"secret": {cfg.RecaptchaSecret},
			"response": {response},
			"remoteip": {remoteip}})
	if err != nil {
		return
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	err = json.Unmarshal(body, &r)
	return
}

func dispense(w http.ResponseWriter, r *http.Request) {
	cfg := getConfig(r)

	err := r.ParseForm()
	if err != nil {
		log.Printf("Error parsing form: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	recaptcha := r.Form.Get("recaptcha")
	recap, err := cfg.checkRecaptcha(r.RemoteAddr, recaptcha)
	if err != nil {
		log.Printf("Error checking RECAPTCHA: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !recap.Success {
		log.Printf("RECAPTCHA failed\n")
		http.Error(w, "RECAPTCHA failed", http.StatusForbidden)
		return
	}

	targets := r.Form["target"]
	if len(targets) != 1 {
		log.Printf("Corrupted target argument\n")
		http.Error(w, "Corrupted target argument", http.StatusBadRequest)
		return
	}

	target := html.EscapeString(targets[0])

	c, ok := client[r.Host]
	if !ok {
		http.Error(w, fmt.Sprintf("didn't find client for host %s", r.Host), http.StatusBadRequest)
		return
	}

	tx, err := c.SendPaymentFromUnencryptedWallet(cfg.Source, target, uint64(cfg.Fee), uint64(cfg.Amount), nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to dispense money - %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(tx.ID().String())
}

func main() {
	flag.Parse()
	http.HandleFunc("/", handler)
	http.HandleFunc("/dispense", dispense)

	tmpl, err := template.New("top").Parse(topPageTemplate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing top page template: %v\n", err)
		os.Exit(1)
	}

	configText, err := os.ReadFile(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read config file (%s): %v\n", *configFile, err)
		os.Exit(1)
	}

	configMap = make(map[string]dispenserSiteConfig)
	err = json.Unmarshal(configText, &configMap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot load config file (%s): %v\n", *configFile, err)
		os.Exit(1)
	}

	client = make(map[string]libgoal.Client)

	var hosts []string
	for h, cfg := range configMap {
		// Make a cache dir for wallet handle tokens
		cacheDir, err := os.MkdirTemp("", "dispenser")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot make temp dir: %v\n", err)
			os.Exit(1)
		}

		// Init libgoal Client
		c, err := libgoal.MakeClientWithBinDir(cfg.ExeDir, cfg.DataDir, cacheDir, libgoal.FullClient)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot init libgoal %v\n", err)
			os.Exit(1)
		}

		client[h] = c

		hosts = append(hosts, h)

		var buf strings.Builder
		err = tmpl.Execute(&buf, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot execute template for site %s: %v\n", h, err)
			os.Exit(1)
		}

		cfg.topPage = buf.String()
		configMap[h] = cfg
	}

	useAutocert := false
	if *autocertDir != "" || *httpsCert == "" || *httpsKey == "" {
		useAutocert = true
	}

	if useAutocert {
		cacheDir := *autocertDir
		if cacheDir == "" {
			cacheDir = os.Getenv("HOME") + "/.autocert"
		}

		m := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(hosts...),
			Cache:      autocert.DirCache(cacheDir),
		}

		go http.ListenAndServe(":80", m.HTTPHandler(nil))
		log.Fatal(http.Serve(m.Listener(), nil))
	} else {
		log.Fatal(http.ListenAndServeTLS(fmt.Sprintf(":%d", *listenPort), *httpsCert, *httpsKey, nil))
	}
}
