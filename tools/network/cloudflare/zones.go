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

package cloudflare

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

func getZonesRequest(authEmail, authKey string) (*http.Request, error) {
	// construct the query
	requestURI, err := url.Parse(cloudFlareURI)
	if err != nil {
		return nil, err
	}
	requestURI.Path = requestURI.Path + "zones"
	request, err := http.NewRequest("GET", requestURI.String(), nil)
	if err != nil {
		return nil, err
	}
	addHeaders(request, authEmail, authKey)
	return request, nil
}

// GetZonesResult is the JSON response for a DNS create request
type GetZonesResult struct {
	Success    bool                 `json:"success"`
	Errors     []interface{}        `json:"errors"`
	Messages   []interface{}        `json:"messages"`
	Result     []GetZonesResultItem `json:"result"`
	ResultInfo GetZonesResultPage   `json:"result_info"`
}

// GetZonesResultPage is the result of the response for the DNS create request
type GetZonesResultPage struct {
	Page       int `json:"page"`
	PerPage    int `json:"per_page"`
	TotalPages int `json:"total_pages"`
	Count      int `json:"count"`
	TotalCount int `json:"total_count"`
}

// GetZonesResultItem is the result of the response for the DNS create request
type GetZonesResultItem struct {
	ID                  string   `json:"id"`
	Name                string   `json:"name"`
	Status              string   `json:"status"`
	Paused              bool     `json:"paused"`
	Type                string   `json:"type"`
	DevelopmentMode     int      `json:"development_mode"`
	NameServers         []string `json:"name_servers"`
	OriginalNameServers []string `json:"original_name_servers"`
}

func parseGetZonesResponse(response *http.Response) (*GetZonesResult, error) {
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Response status code %d", response.StatusCode)
	}
	var parsedReponse GetZonesResult
	if err := json.Unmarshal(body, &parsedReponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body '%s' : %v", string(body), err)
	}
	return &parsedReponse, nil
}

func exportZoneRequest(zoneID, authEmail, authKey string) (*http.Request, error) {
	// construct the query
	requestURI, err := url.Parse(cloudFlareURI)
	if err != nil {
		return nil, err
	}
	requestURI.Path = requestURI.Path + "zones/" + zoneID + "/dns_records/export"
	request, err := http.NewRequest("GET", requestURI.String(), nil)
	if err != nil {
		return nil, err
	}
	addHeaders(request, authEmail, authKey)
	return request, nil
}
