package service

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	Name        = "CrystaLAgent"
	DisplayName = "CA - Behavior Analyst"
)

// handler nhận lệnh start/stop từ Service Control Manager của Windows.
type handler struct {
	run func(ctx context.Context) error
}

func (h *handler) Execute(args []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()

	// Hai cờ cho phép Windows dừng service khi người dùng hoặc hệ thống yêu cầu.
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending}
				// Chờ agent dọn collector và đóng dữ liệu trước khi báo service đã dừng.
				cancel()
				<-done // chờ app dừng sạch
				return false, 0
			}
		case <-done: // app tự thoát (lỗi) thì báo lỗi cho Windows
			return false, 1
		}
	}
}

// IsService cho biết chương trình có đang được Windows chạy như service không.
func IsService() bool {
	ok, _ := svc.IsWindowsService()
	return ok
}

func RunService(run func(ctx context.Context) error) error {
	return svc.Run(Name, &handler{run: run})
}

func Install() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	// StartAutomatic để SCM khởi chạy agent sau mỗi lần Windows khởi động.
	s, err := m.CreateService(Name, exe, mgr.Config{
		DisplayName: DisplayName,
		Description: "Thu thập hành vi tiến trình, mạng và log Windows",
		StartType:   mgr.StartAutomatic, // tự chạy khi bật máy
	})
	if err != nil {
		return fmt.Errorf("tạo service: %w", err)
	}
	defer s.Close()

	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400); err != nil {
		_ = s.Delete()
		return fmt.Errorf("cấu hình tự khởi động lại service: %w", err)
	}
	if err := s.Start(); err != nil {
		_ = s.Delete()
		return fmt.Errorf("đã tạo service nhưng không khởi động được: %w", err)
	}
	return nil
}

func Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Delete()
}

func Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Start()
}

func Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(Name)
	if err != nil {
		return err
	}
	defer s.Close()
	_, err = s.Control(svc.Stop)
	return err
}
