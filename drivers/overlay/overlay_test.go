package overlay

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/docker/docker/pkg/plugingetter"
	"github.com/docker/libkv/store/consul"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/discoverapi"
	"github.com/docker/libnetwork/driverapi"
	"github.com/docker/libnetwork/netlabel"
	_ "github.com/docker/libnetwork/testutils"
	"github.com/vishvananda/netlink/nl"
)

func init() {
	consul.Register()
}

type driverTester struct {
	t *testing.T
	d *driver
}

const testNetworkType = "overlay"

func setupDriver(t *testing.T) *driverTester {
	dt := &driverTester{t: t}
	config := make(map[string]interface{})
	config[netlabel.GlobalKVClient] = discoverapi.DatastoreConfigData{
		Scope:    datastore.GlobalScope,
		Provider: "consul",
		Address:  "127.0.0.01:8500",
	}

	if err := Init(dt, config); err != nil {
		t.Fatal(err)
	}

	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	addrs, err := iface.Addrs()
	if err != nil || len(addrs) == 0 {
		t.Fatal(err)
	}
	data := discoverapi.NodeDiscoveryData{
		Address:     strings.Split(addrs[0].String(), "/")[0],
		BindAddress: strings.Split(addrs[0].String(), "/")[0],
		Self:        true,
	}
	dt.d.DiscoverNew(discoverapi.NodeDiscovery, data)
	return dt
}

func cleanupDriver(t *testing.T, dt *driverTester) {
	ch := make(chan struct{})
	go func() {
		Fini(dt.d)
		close(ch)
	}()

	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatal("test timed out because Fini() did not return on time")
	}
}

func (dt *driverTester) GetPluginGetter() plugingetter.PluginGetter {
	return nil
}

func (dt *driverTester) RegisterDriver(name string, drv driverapi.Driver,
	cap driverapi.Capability) error {
	if name != testNetworkType {
		dt.t.Fatalf("Expected driver register name to be %q. Instead got %q",
			testNetworkType, name)
	}

	if _, ok := drv.(*driver); !ok {
		dt.t.Fatalf("Expected driver type to be %T. Instead got %T",
			&driver{}, drv)
	}

	dt.d = drv.(*driver)
	return nil
}

func TestOverlayInit(t *testing.T) {
	if err := Init(&driverTester{t: t}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestOverlayFiniWithoutConfig(t *testing.T) {
	dt := &driverTester{t: t}
	if err := Init(dt, nil); err != nil {
		t.Fatal(err)
	}

	cleanupDriver(t, dt)
}

func TestOverlayConfig(t *testing.T) {
	dt := setupDriver(t)

	time.Sleep(1 * time.Second)

	d := dt.d
	if d.notifyCh == nil {
		t.Fatal("Driver notify channel wasn't initialized after Config method")
	}

	if d.exitCh == nil {
		t.Fatal("Driver serfloop exit channel wasn't initialized after Config method")
	}

	if d.serfInstance == nil {
		t.Fatal("Driver serfinstance  hasn't been initialized after Config method")
	}

	cleanupDriver(t, dt)
}

func TestOverlayType(t *testing.T) {
	dt := &driverTester{t: t}
	if err := Init(dt, nil); err != nil {
		t.Fatal(err)
	}

	if dt.d.Type() != testNetworkType {
		t.Fatalf("Expected Type() to return %q. Instead got %q", testNetworkType,
			dt.d.Type())
	}
}

// Test that the netlink socket close unblock the watchMiss to avoid deadlock
func TestNetlinkSocket(t *testing.T) {
	// This is the same code used by the overlay driver to create the netlink interface
	// for the watch miss
	nlSock, err := nl.Subscribe(syscall.NETLINK_ROUTE, syscall.RTNLGRP_NEIGH)
	if err != nil {
		t.Fatal()
	}
	// set the receive timeout to not remain stuck on the RecvFrom if the fd gets closed
	tv := unix.NsecToTimeval(soTimeout.Nanoseconds())
	err = nlSock.SetReceiveTimeout(&tv)
	if err != nil {
		t.Fatal()
	}
	n := &network{id: "testnetid"}
	ch := make(chan error)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		n.watchMiss(nlSock, fmt.Sprintf("/proc/%d/task/%d/ns/net", os.Getpid(), syscall.Gettid()))
		ch <- nil
	}()
	time.Sleep(5 * time.Second)
	nlSock.Close()
	select {
	case <-ch:
	case <-ctx.Done():
		{
			t.Fatalf("Timeout expired")
		}
	}
}

func TestEncryptionMissingUpdate(t *testing.T) {
	dt := setupDriver(t)
	d := dt.d

	if d.advertiseAddress == "" || d.bindAddress == "" {
		t.Fatalf("Driver IP addresses not initialized")
	}

	type TestKey struct {
		key []byte
		tag uint64
	}
	var testKeys []TestKey

	for i := 0; i < 40; i++ {
		testKeys = append(testKeys,
			TestKey{
				[]byte(fmt.Sprintf("Key %v", i)),
				uint64(i),
			})
	}

	cfgEnc := discoverapi.DriverEncryptionConfig{}
	updtEnc := discoverapi.DriverEncryptionUpdate{}
	staleIdx, priIdx, newIdx, pruneIdx := 0, 1, 2, 0
	for newIdx+1 < len(testKeys) {
		cfgEnc.Keys = append(cfgEnc.Keys, testKeys[priIdx].key)
		cfgEnc.Tags = append(cfgEnc.Tags, testKeys[priIdx].tag)
		cfgEnc.Keys = append(cfgEnc.Keys, testKeys[newIdx].key)
		cfgEnc.Tags = append(cfgEnc.Tags, testKeys[newIdx].tag)
		cfgEnc.Keys = append(cfgEnc.Keys, testKeys[staleIdx].key)
		cfgEnc.Tags = append(cfgEnc.Tags, testKeys[staleIdx].tag)
		if staleIdx == 0 {
			// initial key setup
			if err := d.DiscoverNew(discoverapi.EncryptionKeysConfig, cfgEnc); err != nil {
				t.Fatal(err)
			}

			// emulate couple remote ep.
			if err := setupEncryption(
				net.ParseIP(d.bindAddress), net.ParseIP(d.advertiseAddress), net.ParseIP("192.1.2.1"),
				4097, d.secMap, d.keys); err != nil {
				t.Fatal(err)
			}
		}
		// new -> prim, prim-> stale, stale-> prune
		pruneIdx = staleIdx
		staleIdx = priIdx
		priIdx = newIdx
		newIdx++

		if rand.Int()&0x3 == 0 {
			// skip 1 of 4.
			t.Logf("Skipping at priIdx %v", priIdx)
			continue
		}
		updtEnc.Primary = testKeys[priIdx].key
		updtEnc.PrimaryTag = testKeys[priIdx].tag
		updtEnc.Key = testKeys[newIdx].key
		updtEnc.Tag = testKeys[newIdx].tag
		updtEnc.Prune = testKeys[pruneIdx].key
		updtEnc.PruneTag = testKeys[pruneIdx].tag

		if err := d.DiscoverNew(
			discoverapi.EncryptionKeysUpdate, []interface{}{updtEnc, cfgEnc}); err != nil {
			t.Fatal(err)
		}
	}
	clearEncryptionStates()
}
