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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strconv"
)

type promMetricFetcher struct {
	promHost string
}

type promValueResult struct {
	timestamp float64
	value     float64
}

func makePromMetricFetcher(host string) *promMetricFetcher {

	return &promMetricFetcher{
		promHost: host,
	}
}

func (r *promMetricFetcher) getMetric(query string) (results []promValueResult, err error) {
	queryURL := fmt.Sprintf("http://%s:9090/api/v1/query", r.promHost)
	req, err := http.NewRequest("GET", queryURL, nil)
	if err != nil {
		return
	}
	q := req.URL.Query()
	q.Add("query", query)
	req.URL.RawQuery = q.Encode()

	httpClient := http.Client{}
	resp, err := httpClient.Do(req /*req.WithContext(ctx)*/)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("http error code received %v", resp.StatusCode)
	}

	bytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	var resultsMap map[string]interface{}
	pathMap := make(map[string]interface{})
	err = json.Unmarshal(bytes, &resultsMap)
	if err != nil {
		return
	}

	r.parseMap("", resultsMap, pathMap)
	for i := 0; ; i++ {
		// ensure that we have /data/result[X]/value[0] and /data/result[X]/value[1]
		tsName := fmt.Sprintf("/data/result[%d]/value[0]", i)
		valName := fmt.Sprintf("/data/result[%d]/value[1]", i)
		_, hasTs := pathMap[tsName]
		_, hasVal := pathMap[valName]
		if !hasTs || !hasVal {
			break
		}

		var tsFloat, valFloat float64
		if flt, ok := pathMap[tsName].(float64); !ok {
			break
		} else {
			tsFloat = flt
		}

		switch concreteVal := pathMap[valName].(type) {
		case float64:
			valFloat = concreteVal
		case uint64:
			valFloat = float64(concreteVal)
		case int64:
			valFloat = float64(concreteVal)
		case string:
			valFloat, _ = strconv.ParseFloat(concreteVal, 64)
		default:
			fmt.Printf("failed : %v %v\n", pathMap[valName], reflect.TypeOf(pathMap[valName]))
			return
		}

		results = append(results, promValueResult{
			timestamp: tsFloat,
			value:     valFloat,
		})
	}

	return results, nil
}

func (r *promMetricFetcher) parseMap(path string, aMap map[string]interface{}, pathMap map[string]interface{}) {
	for key, val := range aMap {
		switch concreteVal := val.(type) {
		case map[string]interface{}:
			r.parseMap(path+"/"+key, val.(map[string]interface{}), pathMap)
		case []interface{}:
			r.parseArray(path+"/"+key, val.([]interface{}), pathMap)
		default:
			//fmt.Println(path+"/"+key, ":", concreteVal)
			pathMap[path+"/"+key] = concreteVal
		}
	}
}

func (r *promMetricFetcher) parseArray(path string, anArray []interface{}, pathMap map[string]interface{}) {
	for i, val := range anArray {
		switch concreteVal := val.(type) {
		case map[string]interface{}:
			r.parseMap(fmt.Sprintf("%s[%d]", path, i), val.(map[string]interface{}), pathMap)
		case []interface{}:
			r.parseArray(fmt.Sprintf("%s[%d]", path, i), val.([]interface{}), pathMap)
		default:
			//fmt.Println(fmt.Sprintf("%s[%d]", path, i), concreteVal)
			pathMap[fmt.Sprintf("%s[%d]", path, i)] = concreteVal
		}
	}
}

func (r *promMetricFetcher) getSingleValue(results []promValueResult) (result float64, err error) {
	if len(results) > 1 {
		return 0.0, fmt.Errorf("unexpected number of results %v", results)
	}
	if len(results) == 0 {
		return 0.0, nil
	}
	return results[0].value, nil
}

//curl http://telemetry.algodev.network:9090/api/v1/query\?query\=max\(algod_ledger_round\)
