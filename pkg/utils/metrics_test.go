package utils

import (
	"testing"
)

func TestVirtualIfacePattern(t *testing.T) {
	tests := []struct {
		name    string
		iface   string
		virtual bool
	}{
		// Linux virtual interfaces
		{"loopback", "lo", true},
		{"docker", "docker0", true},
		{"veth", "veth1234abc", true},
		{"docker bridge", "br-abc123", true},
		{"virbr", "virbr0", true},
		{"vmnet", "vmnet8", true},
		{"tap", "tap0", true},
		{"tun", "tun0", true},
		{"wireguard", "wg0", true},
		{"zerotier", "zt0", true},
		{"tailscale", "tailscale0", true},
		{"cni", "cni0", true},
		// macOS virtual interfaces
		{"utun", "utun0", true},
		{"utun3", "utun3", true},
		{"awdl", "awdl0", true},
		{"llw", "llw0", true},
		{"bridge", "bridge0", true},
		{"anpi", "anpi0", true},
		{"ap", "ap1", true},
		// Windows virtual interfaces
		{"loopback", "Loopback Pseudo-Interface 1", true},
		{"isatap", "isatap.localdomain", true},
		{"teredo", "Teredo Tunneling Pseudo-Interface", true},
		{"6to4", "6to4 Adapter", true},
		// Real interfaces (should NOT match)
		{"ethernet", "eth0", false},
		{"en0", "en0", false},
		{"en1", "en1", false},
		{"wlan", "wlan0", false},
		{"ens", "ens192", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := VirtualIfacePattern.MatchString(tt.iface)
			if got != tt.virtual {
				t.Errorf("VirtualIfacePattern.MatchString(%q) = %v, want %v", tt.iface, got, tt.virtual)
			}
		})
	}
}

func TestIsVirtualFileSystem(t *testing.T) {
	tests := []struct {
		name       string
		device     string
		fstype     string
		mountPoint string
		virtual    bool
	}{
		// Linux virtual filesystems
		{"proc", "", "proc", "/proc", true},
		{"sysfs", "", "sysfs", "/sys", true},
		{"tmpfs", "", "tmpfs", "/run/user/1000", true},
		{"devtmpfs", "", "devtmpfs", "/dev", true},
		{"cgroup2", "", "cgroup2", "/sys/fs/cgroup", true},
		{"loop device", "/dev/loop0", "ext4", "/mnt/snap", true},
		{"run submount", "", "ext4", "/run/media", true},
		{"dev submount", "", "ext4", "/dev/shm", true},
		// macOS virtual mount points
		{"system volume", "", "apfs", "/System", true},
		{"recovery", "", "apfs", "/Volumes/Recovery", true},
		{"swap", "", "apfs", "/private/var/vm", true},
		// Real filesystems
		{"root ext4", "/dev/sda1", "ext4", "/", false},
		{"home ext4", "/dev/sda2", "ext4", "/home", false},
		{"apfs root", "/dev/disk1s1", "apfs", "/", false},
		{"apfs data", "/dev/disk1s2", "apfs", "/System/Volumes/Data", true},
		// macOS real FS types
		{"nullfs virtual", "", "nullfs", "/some/mount", true},
		{"volfs virtual", "", "volfs", "/some/mount", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsVirtualFileSystem(tt.device, tt.fstype, tt.mountPoint)
			if got != tt.virtual {
				t.Errorf("IsVirtualFileSystem(%q, %q, %q) = %v, want %v",
					tt.device, tt.fstype, tt.mountPoint, got, tt.virtual)
			}
		})
	}
}

func TestIsVirtualDisk(t *testing.T) {
	tests := []struct {
		name    string
		disk    string
		virtual bool
	}{
		{"loop", "loop0", true},
		{"ram", "ram0", true},
		{"zram", "zram0", true},
		{"sda", "sda", false},
		{"nvme", "nvme0n1", false},
		{"disk0", "disk0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsVirtualDisk(tt.disk)
			if got != tt.virtual {
				t.Errorf("IsVirtualDisk(%q) = %v, want %v", tt.disk, got, tt.virtual)
			}
		})
	}
}

func TestGetDiskBaseName(t *testing.T) {
	tests := []struct {
		name     string
		disk     string
		baseName string
	}{
		{"nvme partition", "nvme0n1p1", "nvme0n1"},
		{"nvme disk", "nvme0n1", "nvme0n1"},
		{"scsi disk", "sda", "sda"},
		{"scsi partition", "sda1", "sda"},
		{"mac disk", "disk0", "disk0"},
		{"mac partition", "disk0s1", "disk0"},
		{"mmc disk", "mmcblk0", "mmcblk0"},
		{"mmc partition", "mmcblk0p1", "mmcblk0"},
		{"lvm", "dm-0", "dm-0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetDiskBaseName(tt.disk)
			if got != tt.baseName {
				t.Errorf("GetDiskBaseName(%q) = %q, want %q", tt.disk, got, tt.baseName)
			}
		})
	}
}
