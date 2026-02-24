//go:build darwin && cgo

package metrics

/*
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/route.h>
#include <stdlib.h>
#include <string.h>

static int cpu_ticks(unsigned long long *user, unsigned long long *system,
                     unsigned long long *idle, unsigned long long *nice) {
    host_cpu_load_info_data_t info;
    mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
    if (host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO,
                        (host_info_t)&info, &count) != KERN_SUCCESS) {
        return -1;
    }
    *user = info.cpu_ticks[CPU_STATE_USER];
    *system = info.cpu_ticks[CPU_STATE_SYSTEM];
    *idle = info.cpu_ticks[CPU_STATE_IDLE];
    *nice = info.cpu_ticks[CPU_STATE_NICE];
    return 0;
}

static int vm_mem(unsigned long long *active, unsigned long long *wired,
                  unsigned long long *compressed, unsigned long long *pagesize) {
    vm_statistics64_data_t vm;
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    if (host_statistics64(mach_host_self(), HOST_VM_INFO64,
                          (host_info64_t)&vm, &count) != KERN_SUCCESS) {
        return -1;
    }
    vm_size_t ps = 0;
    host_page_size(mach_host_self(), &ps);
    *active = vm.active_count;
    *wired = vm.wire_count;
    *compressed = vm.compressor_page_count;
    *pagesize = (unsigned long long)ps;
    return 0;
}

// net_bytes sums rx/tx over non-loopback interfaces via the routing-table sysctl.
static int net_bytes(unsigned long long *rx, unsigned long long *tx) {
    int mib[6] = {CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0};
    size_t len = 0;
    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) return -1;
    char *buf = malloc(len);
    if (!buf) return -1;
    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) { free(buf); return -1; }
    unsigned long long r = 0, t = 0;
    char *lim = buf + len;
    char *next = buf;
    while (next < lim) {
        struct if_msghdr *ifm = (struct if_msghdr *)next;
        if (ifm->ifm_type == RTM_IFINFO2) {
            struct if_msghdr2 *if2 = (struct if_msghdr2 *)ifm;
            if (!(if2->ifm_flags & IFF_LOOPBACK)) {
                r += if2->ifm_data.ifi_ibytes;
                t += if2->ifm_data.ifi_obytes;
            }
        }
        next += ifm->ifm_msglen;
    }
    free(buf);
    *rx = r;
    *tx = t;
    return 0;
}
*/
import "C"

import "time"

func (c *Collector) cpuPoints() []Point {
	var user, system, idle, nice C.ulonglong
	if C.cpu_ticks(&user, &system, &idle, &nice) != 0 {
		return nil
	}
	idleT := uint64(idle)
	total := uint64(user) + uint64(system) + uint64(idle) + uint64(nice)
	var pts []Point
	if c.hasPrev {
		if v, ok := cpuUsedPct(total, idleT, c.prevCPUTotal, c.prevCPUIdle); ok {
			pts = append(pts, Point{Name: "host.cpu.used_pct", Value: v})
		}
	}
	c.prevCPUTotal = total
	c.prevCPUIdle = idleT
	return pts
}

func (c *Collector) netPoints(now time.Time) []Point {
	var rx, tx C.ulonglong
	if C.net_bytes(&rx, &tx) != 0 {
		return nil
	}
	rxB, txB := uint64(rx), uint64(tx)
	var pts []Point
	if c.hasPrev && !c.prevNetAt.IsZero() {
		dt := now.Sub(c.prevNetAt).Seconds()
		if dt > 0 && rxB >= c.prevNetRx && txB >= c.prevNetTx {
			pts = append(pts,
				Point{Name: "host.net.rx_bytes_per_sec", Value: float64(rxB-c.prevNetRx) / dt},
				Point{Name: "host.net.tx_bytes_per_sec", Value: float64(txB-c.prevNetTx) / dt},
			)
		}
	}
	c.prevNetRx = rxB
	c.prevNetTx = txB
	c.prevNetAt = now
	return pts
}

func vmMemPoints(total uint64) []Point {
	var active, wired, compressed, pagesize C.ulonglong
	if C.vm_mem(&active, &wired, &compressed, &pagesize) != 0 || pagesize == 0 || total == 0 {
		return nil
	}
	usedBytes := (uint64(active) + uint64(wired) + uint64(compressed)) * uint64(pagesize)
	pct := float64(usedBytes) / float64(total) * 100
	if pct > 100 {
		pct = 100
	}
	return []Point{
		{Name: "host.mem.used_pct", Value: pct},
		{Name: "host.mem.available_kb", Value: float64(total-usedBytes) / 1024},
	}
}
