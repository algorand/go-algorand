// Copyright (C) 2019-2020 Algorand, Inc.
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

// +build windows

package dnssec

import (
	"fmt"
	"runtime/debug"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	dll               = windows.NewLazyDLL("iphlpapi.dll")
	networkParamsProc = dll.NewProc("GetNetworkParams")
)

// values from https://referencesource.microsoft.com/#System/net/System/Net/NetworkInformation/UnSafeNetInfoNativemethods.cs,c5dd09342271faba,references
const (
	max_hostname_len    = 128
	max_domain_name_len = 128
	max_scope_id_len    = 256
)

const ip_size = 16

// typedef struct _IP_ADDR_STRING {
// 	struct _IP_ADDR_STRING *Next;
// 	IP_ADDRESS_STRING      IpAddress;  // The String member is a char array of size 16. This array holds an IPv4 address in dotted decimal notation.
// 	IP_MASK_STRING         IpMask;     // The String member is a char array of size 16. This array holds the IPv4 subnet mask in dotted decimal notation.
// 	DWORD                  Context;
//   } IP_ADDR_STRING, *PIP_ADDR_STRING;
//
// https://docs.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_addr_string
type ipAddrString struct {
	Next      uintptr
	IpAddress [ip_size]uint8
	IpMask    [ip_size]uint8
	Context   uint32
}

// typedef struct {
// 	char            HostName[MAX_HOSTNAME_LEN + 4];
// 	char            DomainName[MAX_DOMAIN_NAME_LEN + 4];
// 	PIP_ADDR_STRING CurrentDnsServer;
// 	IP_ADDR_STRING  DnsServerList;
// 	UINT            NodeType;
// 	char            ScopeId[MAX_SCOPE_ID_LEN + 4];
// 	UINT            EnableRouting;
// 	UINT            EnableProxy;
// 	UINT            EnableDns;
//   } FIXED_INFO_W2KSP1, *PFIXED_INFO_W2KSP1;
//
// https://docs.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-fixed_info_w2ksp1
type fixedInfo struct {
	HostName         [max_hostname_len + 4]uint8
	DomainName       [max_domain_name_len + 4]uint8
	CurrentDnsServer uintptr
	DnsServerList    ipAddrString
	NodeType         uint32
	ScopeId          [max_scope_id_len + 4]uint8
	EnableRouting    uint32
	EnableProxy      uint32
	EnableDns        uint32
}

const ipAddrStringSizeof = 48

type fixedInfoWithOverlay struct {
	fixedInfo
	overlay [ipAddrStringSizeof * 32]uint8 // space for max 32 IP_ADDR_STRING entries in the overlay
}

func SystemConfig() (servers []ResolverAddress, timeout time.Duration, err error) {
	// disable GC to prevent fi collection earlier than lookups in fi completed
	pct := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(pct)

	var fi fixedInfoWithOverlay
	var ulSize uint32 = uint32(unsafe.Sizeof(fi))
	ret, _, _ := networkParamsProc.Call(
		uintptr(unsafe.Pointer(&fi)),
		uintptr(unsafe.Pointer(&ulSize)),
	)
	if ret != 0 {
		if windows.Errno(ret) == windows.ERROR_BUFFER_OVERFLOW {
			err = fmt.Errorf("GetNetworkParams requested %d bytes of memory, max supported is %d. Error code is %x", ulSize, unsafe.Sizeof(fi), ret)
			return
		}
		err = fmt.Errorf("GetNetworkParams failed with code is %x", ret)
		return
	}

	var p *ipAddrString = &fi.DnsServerList
	for {
		ip := make([]byte, ip_size)
		for i := 0; i < len(p.IpAddress) && p.IpAddress[i] != 0; i++ {
			ip[i] = p.IpAddress[i]
		}
		servers = append(servers, MakeResolverAddress(string(ip), "53"))

		if p.Next == 0 {
			break
		}
		p = (*ipAddrString)(unsafe.Pointer(p.Next))
	}
	timeout = DefaultTimeout
	return
}
