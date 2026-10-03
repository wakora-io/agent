//go:build linux

package metrics

import "testing"

type fakeNet struct {
	device, bridge, port map[string]bool
}

func (f fakeNet) hasDevice(n string) bool    { return f.device[n] }
func (f fakeNet) isBridge(n string) bool     { return f.bridge[n] }
func (f fakeNet) isBridgePort(n string) bool { return f.port[n] }

const netdevHeader = "Inter-|   Receive                                                |  Transmit\n face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"

func netdevLine(name string, rx, tx string) string {
	return name + ": " + rx + " 0 0 0 0 0 0 0 " + tx + " 0 0 0 0 0 0 0\n"
}

func TestDockerHostCountsOnlyThePhysicalUplink(t *testing.T) {
	dev := netdevHeader +
		netdevLine("lo", "999", "999") +
		netdevLine("ens18", "1000", "2000") +
		netdevLine("docker0", "700", "300") +
		netdevLine("veth1a2b", "300", "700")
	rx, tx := sumUplinks(dev, fakeNet{device: map[string]bool{"ens18": true}, bridge: map[string]bool{"docker0": true}, port: map[string]bool{"veth1a2b": true}})
	if rx != 1000 || tx != 2000 {
		t.Fatalf("rx=%d tx=%d, want 1000/2000 (container traffic counted again)", rx, tx)
	}
}

func TestProxmoxNodeCountsTheNicNotTheBridgeOrGuestTaps(t *testing.T) {
	dev := netdevHeader +
		netdevLine("eno1", "5000", "6000") +
		netdevLine("vmbr0", "4000", "5000") +
		netdevLine("tap101i0", "900", "800") +
		netdevLine("veth102i0", "100", "200")
	rx, tx := sumUplinks(dev, fakeNet{
		device: map[string]bool{"eno1": true},
		bridge: map[string]bool{"vmbr0": true},
		port:   map[string]bool{"eno1": true, "tap101i0": true, "veth102i0": true},
	})
	if rx != 5000 || tx != 6000 {
		t.Fatalf("rx=%d tx=%d, want 5000/6000", rx, tx)
	}
}

func TestContainerWithoutDevicesCountsItsOwnInterface(t *testing.T) {
	dev := netdevHeader +
		netdevLine("lo", "1", "1") +
		netdevLine("eth0", "800", "900") +
		netdevLine("docker0", "50", "60") +
		netdevLine("vethc0de", "60", "50")
	rx, tx := sumUplinks(dev, fakeNet{bridge: map[string]bool{"docker0": true}, port: map[string]bool{"vethc0de": true}})
	if rx != 800 || tx != 900 {
		t.Fatalf("rx=%d tx=%d, want 800/900", rx, tx)
	}
}

func TestBondSlavesAreSummed(t *testing.T) {
	dev := netdevHeader +
		netdevLine("bond0", "300", "300") +
		netdevLine("eth0", "100", "200") +
		netdevLine("eth1", "200", "100")
	rx, tx := sumUplinks(dev, fakeNet{device: map[string]bool{"eth0": true, "eth1": true}})
	if rx != 300 || tx != 300 {
		t.Fatalf("rx=%d tx=%d, want 300/300", rx, tx)
	}
}
