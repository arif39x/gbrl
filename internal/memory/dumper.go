// Package memory provides process memory inspection and forensic dumping
// facilities. It reads /proc/<pid>/maps to identify memory regions and uses
// process_vm_readv to capture their contents for offline analysis.
package memory

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const magic = "GBRL"
const version = uint32(1)

type regionInfo struct {
	Start  uint64
	End    uint64
	Perms  string
	Offset uint64
	Dev    string
	Inode  uint64
	Path   string
}

func (r regionInfo) Readable() bool {
	return len(r.Perms) > 0 && r.Perms[0] == 'r'
}

func (r regionInfo) Special() bool {
	return r.Path == "" || strings.HasPrefix(r.Path, "[") ||
		strings.Contains(r.Path, "/dev/") ||
		strings.Contains(r.Path, "/memfd:")
}

// Dump captures readable memory regions from a process by reading /proc/<pid>/maps
// and writes them to outputPath in a structured binary format.
func Dump(pid int, outputPath string) error {
	regions, err := readMaps(pid)
	if err != nil {
		return fmt.Errorf("read maps: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create dump file: %w", err)
	}
	defer f.Close()

	hdr := make([]byte, 4+4+8+8+4)
	copy(hdr[0:4], magic)
	binary.LittleEndian.PutUint32(hdr[4:8], version)
	binary.LittleEndian.PutUint64(hdr[8:16], uint64(time.Now().UnixNano()))
	binary.LittleEndian.PutUint64(hdr[16:24], uint64(pid))

	var dumpCount uint32
	// We'll write numRegions after counting
	regionOffset := 24
	f.Write(hdr[:regionOffset])

	for _, r := range regions {
		if !r.Readable() || r.Special() {
			continue
		}
		data, err := ReadBytes(pid, uintptr(r.Start), int(r.End-r.Start))
		if err != nil {
			continue
		}
		perms := []byte(r.Perms)
		entry := make([]byte, 8+8+4+len(perms)+8+len(data))
		binary.LittleEndian.PutUint64(entry[0:8], r.Start)
		binary.LittleEndian.PutUint64(entry[8:16], r.End)
		binary.LittleEndian.PutUint32(entry[16:20], uint32(len(perms)))
		copy(entry[20:20+len(perms)], perms)
		binary.LittleEndian.PutUint64(entry[20+len(perms):28+len(perms)], uint64(len(data)))
		copy(entry[28+len(perms):], data)
		f.Write(entry)
		dumpCount++
	}

	// Write region count back at offset 24
	f.Seek(int64(regionOffset-4), 0)
	numBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(numBuf, dumpCount)
	f.Write(numBuf)

	return nil
}

// DumpToDir captures a memory dump to a timestamped file in /tmp and returns its path.
func DumpToDir(pid int) (string, error) {
	ts := time.Now().UnixNano()
	path := filepath.Join("/tmp", fmt.Sprintf("gbrl_dump_%d_%d.bin", pid, ts))
	if err := Dump(pid, path); err != nil {
		return "", err
	}
	return path, nil
}

func readMaps(pid int) ([]regionInfo, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	var regions []regionInfo
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		r, err := parseMapLine(line)
		if err != nil {
			continue
		}
		regions = append(regions, r)
	}
	return regions, nil
}

func parseMapLine(line string) (regionInfo, error) {
	var r regionInfo
	// Format: start-end perms offset dev inode pathname
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return r, fmt.Errorf("invalid map line")
	}
	addrParts := strings.SplitN(fields[0], "-", 2)
	if len(addrParts) != 2 {
		return r, fmt.Errorf("invalid address range")
	}
	start, err := strconv.ParseUint(addrParts[0], 16, 64)
	if err != nil {
		return r, err
	}
	end, err := strconv.ParseUint(addrParts[1], 16, 64)
	if err != nil {
		return r, err
	}
	r.Start = start
	r.End = end
	r.Perms = fields[1]
	if len(fields) > 5 {
		r.Path = fields[5]
	}
	return r, nil
}
