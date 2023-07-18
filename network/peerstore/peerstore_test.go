package peerstore

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"

	libp2p_crypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2p "github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
)

func TestPeerstore(t *testing.T) {
	peerAddrs := []string{
		"/dns4/ams-2.bootstrap.libp2p.io/tcp/443/wss/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Nb",
		"/ip4/147.75.83.83/tcp/4001/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj75Na",
		"/ip6/2604:1380:2000:7a00::1/udp/4001/quic/p2p/QmbLHAnMoJPWSCR5Zhtx6BHJX9KiKNN6tpvbUcqanj73Nb",
		"/ip4/198.51.100.0/tcp/4242/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N",
	}

	ps, err := NewPeerStore(context.Background(), "", peerAddrs)
	require.NoError(t, err)
	defer ps.Close()

	// peerstore is initialized with addresses
	peers := ps.PeersWithAddrs()
	require.Equal(t, 4, len(peers))

	// add peer addresses
	var addrs []string
	var peerIDS []peer.ID
	for i := 0; i < 4; i++ {
		privKey, _, err := libp2p_crypto.GenerateEd25519Key(rand.Reader)
		require.NoError(t, err)
		peerID, err := peer.IDFromPrivateKey(privKey)
		require.NoError(t, err)
		peerIDS = append(peerIDS, peerID)
		maddrStr := fmt.Sprintf("/ip4/1.2.3.4/tcp/%d/p2p/%s", 4000+i, peerID.String())
		addrs = append(addrs, maddrStr)
	}
	for _, addr := range addrs {
		info, err := ps.PeerInfoFromAddrString(addr)
		require.NoError(t, err)
		ps.AddAddrs(info.ID, info.Addrs, libp2p.PermanentAddrTTL)
	}

	// peerstore should have 6 peers now
	peers = ps.PeersWithAddrs()
	require.Equal(t, 8, len(peers))

	// remove a peer addr
	ps.Peerstore.ClearAddrs(peerIDS[0])
	peers = ps.PeersWithAddrs()
	require.Equal(t, 7, len(peers))

}
