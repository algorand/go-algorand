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
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	cloudFlareURI = "https://api.cloudflare.com/client/v4/"
	// AutomaticTTL should be used to request cloudflare's Automatic TTL setting (which is 1).
	AutomaticTTL = 1
)

// ErrUserNotPermitted is used when a user that is not permitted in a given zone attempt to perform an operation on that zone.
var ErrUserNotPermitted = fmt.Errorf("user not permitted in zone")

// ErrDuplicateZoneNameFound is used when a user that is not permitted in a given zone attempt to perform an operation on that zone.
var ErrDuplicateZoneNameFound = fmt.Errorf("more than a single zone name found to match the requested zone name")

// Cred contains the credentials used to authenticate with the cloudflare API.
type Cred struct {
	authEmail string
	authKey   string
}

// DNS is the cloudflare package main access class. Initiate an instance of this class to access the clouldflare APIs.
type DNS struct {
	zoneID string
	Cred
}

// NewCred creates a new credential structure used to authenticate with the cloudflare service.
func NewCred(authEmail string, authKey string) *Cred {
	return &Cred{
		authEmail: authEmail,
		authKey:   authKey,
	}
}

// NewDNS create a new instance of clouldflare DNS services class
func NewDNS(zoneID string, authEmail string, authKey string) *DNS {
	return &DNS{
		zoneID: zoneID,
		Cred: Cred{
			authEmail: authEmail,
			authKey:   authKey,
		},
	}
}

// SetDNSRecord sets the DNS record to the given content.
func (d *DNS) SetDNSRecord(ctx context.Context, recordType string, name string, content string, ttl uint, priority uint, proxied bool) error {
	entries, err := d.ListDNSRecord(ctx, "", name, "", "", "", "")
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		fmt.Printf("DNS entry for '%s'='%s' already exists, updating.\n", name, content)
		return d.UpdateDNSRecord(ctx, entries[0].ID, recordType, name, content, ttl, priority, proxied)
	}
	return d.CreateDNSRecord(ctx, recordType, name, content, ttl, priority, proxied)
}

// SetSRVRecord sets the DNS SRV record to the given content.
func (d *DNS) SetSRVRecord(ctx context.Context, name string, target string, ttl uint, priority uint, port uint, service string, protocol string, weight uint) error {
	entries, err := d.ListDNSRecord(ctx, "SRV", service+"."+protocol+"."+name, target, "", "", "")

	if err != nil {
		return err
	}
	if len(entries) != 0 {
		fmt.Printf("SRV entry for '%s'='%s' already exists, updating\n", name, target)
		return d.UpdateSRVRecord(ctx, entries[0].ID, name, target, ttl, priority, port, service, protocol, weight)
	}

	return d.CreateSRVRecord(ctx, name, target, ttl, priority, port, service, protocol, weight)
}

// ClearSRVRecord clears the DNS SRV record to the given content.
func (d *DNS) ClearSRVRecord(ctx context.Context, name string, target string, service string, protocol string) error {
	entries, err := d.ListDNSRecord(ctx, "SRV", service+"."+protocol+"."+name, target, "", "", "")

	if err != nil {
		return err
	}
	if len(entries) == 0 {
		fmt.Printf("No SRV entry for '[%s.%s.]%s'='%s'.\n", service, protocol, name, target)
		return nil
	}

	return d.DeleteDNSRecord(ctx, entries[0].ID)
}

// ListDNSRecord list the dns records that matches the given parameters.
func (d *DNS) ListDNSRecord(ctx context.Context, recordType string, name string, content string, order string, direction string, match string) ([]DNSRecordResponseEntry, error) {
	result := []DNSRecordResponseEntry{}
	const perPage uint = 100
	pageIndex := uint(1)
	queryContent := content
	if recordType == "SRV" {
		queryContent = ""
	}
	for {
		request, err := listDNSRecordRequest(d.zoneID, d.authEmail, d.authKey, recordType, name, queryContent, pageIndex, perPage, order, direction, match)
		if err != nil {
			return []DNSRecordResponseEntry{}, err
		}
		client := &http.Client{}
		response, err := client.Do(request.WithContext(ctx))
		if err != nil {
			return []DNSRecordResponseEntry{}, err
		}

		parsedReponse, err := parseListDNSRecordResponse(response)
		if err != nil {
			return []DNSRecordResponseEntry{}, fmt.Errorf("failed to list DNS records. Request url = '%v', response error : %v", request.URL, err)
		}
		if len(parsedReponse.Errors) > 0 {
			return []DNSRecordResponseEntry{}, fmt.Errorf("Failed to list DNS entries. %+v", parsedReponse.Errors)
		}
		result = append(result, parsedReponse.Result...)
		if parsedReponse.ResultInfo.TotalPages <= int(pageIndex) {
			break
		}
		pageIndex++
	}
	if recordType == "SRV" && content != "" {
		content = strings.ToLower(content)
		for i := len(result) - 1; i >= 0; i-- {
			if !strings.HasSuffix(strings.ToLower(result[i].Content), content) {
				result = append(result[:i], result[i+1:]...)
			}
		}
	}
	return result, nil
}

// CreateDNSRecord creates the DNS record with the given content.
func (d *DNS) CreateDNSRecord(ctx context.Context, recordType string, name string, content string, ttl uint, priority uint, proxied bool) error {
	request, err := createDNSRecordRequest(d.zoneID, d.authEmail, d.authKey, recordType, name, content, ttl, priority, proxied)
	if err != nil {
		return err
	}
	client := &http.Client{}
	response, err := client.Do(request.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("failed to create DNS record. Request url = '%v', response : %v", request.URL, err)
	}

	parsedResponse, err := parseCreateDNSRecordResponse(response)
	if err != nil {
		return fmt.Errorf("failed to create DNS record. Request url = '%v', response error : %v", request.URL, err)
	}
	if parsedResponse.Success == false {
		request, _ := createDNSRecordRequest(d.zoneID, d.authEmail, d.authKey, recordType, name, content, ttl, priority, proxied)
		requestBody, _ := request.GetBody()
		bodyBytes, _ := ioutil.ReadAll(requestBody)
		return fmt.Errorf("failed to create DNS record. Request url = '%v', body = %s, parsed response : %#v, response headers = %#v", request.URL, string(bodyBytes), parsedResponse, response.Header)
	}
	return nil
}

// CreateSRVRecord creates the DNS record with the given content.
func (d *DNS) CreateSRVRecord(ctx context.Context, name string, target string, ttl uint, priority uint, port uint, service string, protocol string, weight uint) error {
	request, err := createSRVRecordRequest(d.zoneID, d.authEmail, d.authKey, name, service, protocol, weight, port, ttl, priority, target)
	if err != nil {
		return err
	}
	client := &http.Client{}
	response, err := client.Do(request.WithContext(ctx))
	if err != nil {
		return fmt.Errorf("failed to create SRV record. Request url = '%v', response : %v", request.URL, err)
	}

	parsedResponse, err := parseCreateDNSRecordResponse(response)
	if err != nil {
		return fmt.Errorf("failed to create SRV record. Request url = '%v', response error : %v", request.URL, err)
	}
	if parsedResponse.Success == false {
		request, _ := createSRVRecordRequest(d.zoneID, d.authEmail, d.authKey, name, service, protocol, weight, port, ttl, priority, target)
		requestBody, _ := request.GetBody()
		bodyBytes, _ := ioutil.ReadAll(requestBody)
		return fmt.Errorf("failed to create SRV record. Request url = '%v', body = %s, parsedResponse = %#v, response headers = %#v", request.URL, string(bodyBytes), parsedResponse, response.Header)
	}
	return nil
}

// DeleteDNSRecord deletes a single DNS entry
func (d *DNS) DeleteDNSRecord(ctx context.Context, recordID string) error {
	request, err := deleteDNSRecordRequest(d.zoneID, d.authEmail, d.authKey, recordID)
	if err != nil {
		return err
	}
	client := &http.Client{}
	response, err := client.Do(request.WithContext(ctx))
	if err != nil {
		return err
	}

	parsedResponse, err := parseDeleteDNSRecordResponse(response)
	if err != nil {
		return fmt.Errorf("failed to delete DNS record. Request url = '%v', response error : %v", request.URL, err)
	}
	if parsedResponse.Success == false {
		request, _ := deleteDNSRecordRequest(d.zoneID, d.authEmail, d.authKey, recordID)
		requestBody, _ := request.GetBody()
		bodyBytes, _ := ioutil.ReadAll(requestBody)
		return fmt.Errorf("failed to delete DNS record. Request url = '%v', body = %s, parsedResponse = %#v, response headers = %#v", request.URL, string(bodyBytes), parsedResponse, response.Header)
	}
	return nil
}

// UpdateDNSRecord update the DNS record with the given content.
func (d *DNS) UpdateDNSRecord(ctx context.Context, recordID string, recordType string, name string, content string, ttl uint, priority uint, proxied bool) error {
	request, err := updateDNSRecordRequest(d.zoneID, d.authEmail, d.authKey, recordID, recordType, name, content, ttl, priority, proxied)
	if err != nil {
		return err
	}
	client := &http.Client{}
	response, err := client.Do(request.WithContext(ctx))
	if err != nil {
		return err
	}

	parsedResponse, err := parseUpdateDNSRecordResponse(response)
	if err != nil {
		return fmt.Errorf("failed to update DNS record. Request url = '%v', response error : %v", request.URL, err)
	}

	if parsedResponse.Success == false {
		request, _ := updateDNSRecordRequest(d.zoneID, d.authEmail, d.authKey, recordID, recordType, name, content, ttl, priority, proxied)
		requestBody, _ := request.GetBody()
		bodyBytes, _ := ioutil.ReadAll(requestBody)
		return fmt.Errorf("failed to update DNS record. Request url = '%v', body = %s, parsedResponse = %#v, response headers = %#v", request.URL, string(bodyBytes), parsedResponse, response.Header)
	}

	return nil
}

// UpdateSRVRecord update the DNS record with the given content.
func (d *DNS) UpdateSRVRecord(ctx context.Context, recordID string, name string, target string, ttl uint, priority uint, port uint, service string, protocol string, weight uint) error {
	request, err := updateSRVRecordRequest(d.zoneID, d.authEmail, d.authKey, recordID, name, service, protocol, weight, port, ttl, priority, target)
	if err != nil {
		return err
	}
	client := &http.Client{}
	response, err := client.Do(request.WithContext(ctx))
	if err != nil {
		return err
	}

	parsedResponse, err := parseUpdateDNSRecordResponse(response)
	if err != nil {
		return fmt.Errorf("failed to update SRV record. Request url = '%v', response error : %v", request.URL, err)
	}
	if parsedResponse.Success == false {
		request, _ := updateSRVRecordRequest(d.zoneID, d.authEmail, d.authKey, recordID, name, service, protocol, weight, port, ttl, priority, target)
		requestBody, _ := request.GetBody()
		bodyBytes, _ := ioutil.ReadAll(requestBody)
		return fmt.Errorf("failed to update SRV record. Request url = '%v', body = %s, parsedResponse = %#v, response headers = %#v", request.URL, string(bodyBytes), parsedResponse, response.Header)
	}
	return nil
}

// Zone represent a single zone on the cloudflare API.
type Zone struct {
	DomainName string
	ZoneID     string
}

// GetZones returns a list of zones that are associated with cloudflare.
func (c *Cred) GetZones(ctx context.Context) (zones []Zone, err error) {
	request, err := getZonesRequest(c.authEmail, c.authKey)
	if err != nil {
		return nil, err
	}
	client := &http.Client{}
	response, err := client.Do(request.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	parsedResponse, err := parseGetZonesResponse(response)
	if err != nil {
		return nil, fmt.Errorf("failed to get zones. Request url = '%v', response error : %v", request.URL, err)
	}
	if parsedResponse.Success == false {
		request, _ := getZonesRequest(c.authEmail, c.authKey)
		requestBody, _ := request.GetBody()
		bodyBytes, _ := ioutil.ReadAll(requestBody)
		return nil, fmt.Errorf("failed to retrieve zone records. Request url = '%v', body = %s, parsedResponse = %#v, response headers = %#v", request.URL, string(bodyBytes), parsedResponse, response.Header)
	}

	for _, z := range parsedResponse.Result {
		zones = append(zones,
			Zone{
				DomainName: z.Name,
				ZoneID:     z.ID,
			},
		)
	}
	return zones, err
}

// GetZoneID returns a zoneID that matches the requested zoneDomainName.
func (c *Cred) GetZoneID(ctx context.Context, zoneDomainName string) (zoneID string, err error) {
	zones, err := c.GetZones(ctx)
	if err != nil {
		return
	}
	if len(zones) == 0 {
		err = ErrUserNotPermitted
		return
	}
	zoneDomainName = strings.ToLower(zoneDomainName)
	var matchingZone Zone
	for _, zone := range zones {
		if zoneDomainName == strings.ToLower(zone.DomainName) {
			// found a match.
			if matchingZone.ZoneID != "" {
				// we already had a previous match ?!
				err = ErrDuplicateZoneNameFound
				return
			}
			matchingZone = zone
		}
	}
	if matchingZone.ZoneID == "" {
		err = fmt.Errorf("no zones matching %s for specified credentials", zoneDomainName)
		return
	}
	return matchingZone.ZoneID, nil
}

// ExportZone exports the zone into a BIND config bytes array
func (d *DNS) ExportZone(ctx context.Context) (exportedZoneBytes []byte, err error) {
	request, err := exportZoneRequest(d.zoneID, d.authEmail, d.authKey)
	if err != nil {
		return nil, err
	}
	client := &http.Client{}
	response, err := client.Do(request.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}
