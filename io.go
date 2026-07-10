package receipt

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// EntryCount returns the number of recorded entries (concurrency-safe).
func (r *Receipt) EntryCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.Entries)
}

// ReceiptsDir is the directory where finalized receipts are written.
func ReceiptsDir() (string, error) {
	return receiptsDir()
}

// Load reads and parses a receipt JSON file from disk.
func Load(path string) (*Receipt, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read receipt: %w", err)
	}
	var r Receipt
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse receipt: %w", err)
	}
	return &r, nil
}

// List returns the paths of all receipt files, newest filesystem-modified last.
func List() ([]string, error) {
	dir, err := receiptsDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	type item struct {
		path  string
		mtime int64
	}
	var items []item
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		items = append(items, item{filepath.Join(dir, e.Name()), info.ModTime().UnixNano()})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].mtime < items[j].mtime })
	paths := make([]string, len(items))
	for i, it := range items {
		paths[i] = it.path
	}
	return paths, nil
}
