//go:build windows

package jsonfile

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// A kernel byte-range lock survives neither process exit nor machine restart.
// The .writer.lock file itself may remain; it is NOT a stale-lock indicator.
type writerLock struct {
	file *os.File
	overlapped windows.Overlapped
}

func acquireWriterLock(path string) (*writerLock, error) {
	f, err := os.OpenFile(path+".writer.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	l := &writerLock{file: f}
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &l.overlapped)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("LockFileEx: %w", err)
	}
	return l, nil
}

func (l *writerLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &l.overlapped)
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(err, closeErr)
}
