package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// A single process owns each private state file. Updates are atomic, fsynced
// replacements in an existing owner-only directory; no symlink paths accepted.
type privateState struct {
	path string
	lock *os.File
}

func ownedPrivate(info os.FileInfo, directory bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm()&0077 == 0 && ((directory && info.IsDir()) || (!directory && info.Mode().IsRegular()))
}
func trustedWorkloadConfig(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ownedPrivate(info, false) || (ok && stat.Uid == 0 && info.Mode().IsRegular() && info.Mode().Perm()&0027 == 0)
}
func openPrivateState(path string) (*privateState, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("state requires an absolute clean filename")
	}
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil || !ownedPrivate(dir, true) {
		return nil, errors.New("state directory must be owned by this process and private")
	}
	if info, err := os.Lstat(path); err == nil {
		if !ownedPrivate(info, false) {
			return nil, errors.New("state file must be owned by this process and private")
		}
	} else if !os.IsNotExist(err) {
		return nil, errors.New("state file is unavailable")
	}
	lockPath := path + ".lock"
	if info, err := os.Lstat(lockPath); err == nil && !ownedPrivate(info, false) {
		return nil, errors.New("unsafe state lock file")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, errors.New("state lock is unavailable")
	}
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.New("state lock is unavailable")
	}
	if info, err := lock.Stat(); err != nil || !ownedPrivate(info, false) || syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		lock.Close()
		return nil, errors.New("private state is unsafe or already in use")
	}
	return &privateState{path: path, lock: lock}, nil
}
func (s *privateState) close() { _ = s.lock.Close() }
func (s *privateState) read(output any) (bool, error) {
	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("private state is unavailable")
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !ownedPrivate(info, false) {
		return false, errors.New("private state permissions are unsafe")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxResponse+1))
	if err != nil || len(b) > maxResponse || uniqueJSON(b) != nil || json.Unmarshal(b, output) != nil {
		return false, errors.New("private state is malformed")
	}
	return true, nil
}
func (s *privateState) write(input any) error {
	b, err := json.MarshalIndent(input, "", "  ")
	if err != nil || len(b) > maxResponse {
		return errors.New("private state exceeds its limit")
	}
	f, err := os.CreateTemp(filepath.Dir(s.path), ".tailgate-state-")
	if err != nil {
		return errors.New("private state cannot be staged")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if f.Chmod(0600) != nil {
		return errors.New("private state permissions failed")
	}
	if _, err = f.Write(append(b, '\n')); err != nil || f.Sync() != nil || f.Close() != nil || os.Rename(f.Name(), s.path) != nil {
		return errors.New("private state update failed")
	}
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return errors.New("private state durability is uncertain")
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return errors.New("private state durability is uncertain")
	}
	return nil
}
