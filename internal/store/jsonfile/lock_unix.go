//go:build !windows

package jsonfile

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

type writerLock struct { file *os.File }

func acquireWriterLock(path string) (*writerLock, error) {
	f, err := os.OpenFile(path+".writer.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("flock: %w", err)
	}
	return &writerLock{file:f}, nil
}

func (l *writerLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	closeErr := l.file.Close()
	l.file = nil
	return errors.Join(err, closeErr)
}
