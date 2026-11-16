//go:build windows

package collector

import (
	"context"
	"encoding/xml"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"AegisPlus/CrystaL/internal/model"

	"golang.org/x/sys/windows"
)

var (
	wevtapi               = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe      = wevtapi.NewProc("EvtSubscribe")
	procEvtNext           = wevtapi.NewProc("EvtNext")
	procEvtRender         = wevtapi.NewProc("EvtRender")
	procEvtClose          = wevtapi.NewProc("EvtClose")
	procEvtCreateBookmark = wevtapi.NewProc("EvtCreateBookmark")
	procEvtUpdateBookmark = wevtapi.NewProc("EvtUpdateBookmark")
)

const (
	evtSubscribeToFutureEvents     = 1
	evtSubscribeStartAfterBookmark = 3
	evtRenderEventXML              = 1
	evtRenderBookmark              = 2
)

type evtHandle uintptr

type eventLogCollector struct {
	id, channel, query string
	load               func(id string) (string, int64, error)
	save               func(id, bm string, rec int64) error
	mu                 sync.Mutex
	health             model.CollectorHealth
}

func newEventLog(ch model.Channel, load func(string) (string, int64, error), save func(string, string, int64) error) *eventLogCollector {
	return &eventLogCollector{
		id:      "eventlog:" + ch.Name,
		channel: ch.Name,
		query:   ch.Query,
		load:    load,
		save:    save,
		health:  model.CollectorHealth{CollectorID: "eventlog:" + ch.Name, Status: "starting"},
	}
}

func (c *eventLogCollector) ID() string { return c.id }
func (c *eventLogCollector) Health() model.CollectorHealth {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.health
}

func (c *eventLogCollector) setHealth(status, reason, priv, errStr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.health.Status = status
	c.health.Reason = reason
	c.health.PrivilegeStatus = priv
	if errStr != "" {
		c.health.LastError = errStr
		c.health.LastErrorAt = time.Now().UTC()
	}
	if status == "available" {
		c.health.LastSuccessAt = time.Now().UTC()
	}
}

func (c *eventLogCollector) Run(ctx context.Context, emit func(model.CollectorRecord) error) error {
	// Bookmark cho phép tiếp tục từ vị trí đã lưu sau khi agent khởi động lại.
	// Nếu chưa có bookmark, collector đăng ký nhận event mới thay vì đọc toàn bộ lịch sử.
	bookmarkXML, _, _ := c.load(c.id)
	sub, bookmark, signal, err := c.subscribe(bookmarkXML)
	if err != nil {
		st, reason, priv := ClassifyWinErr(err)
		if reason == "no_events" {
			st, reason, priv = "available", "idle", "ok"
		}
		c.setHealth(st, reason, priv, err.Error())
		<-ctx.Done()
		return nil
	}
	defer evtClose(sub)
	if bookmark != 0 {
		defer evtClose(bookmark)
	}
	if signal != 0 {
		defer windows.CloseHandle(signal)
	}
	c.setHealth("available", "subscribed", "ok", "")

	events := make([]evtHandle, 16)
	for {
		if ctx.Err() != nil {
			c.flushBookmark(bookmark)
			return nil
		}
		_, _ = windows.WaitForSingleObject(signal, 500)
		n, err := evtNext(sub, events)
		if err != nil {
			st, reason, priv := ClassifyWinErr(err)
			if reason == "no_events" || st == "available" {
				continue
			}
			c.setHealth(st, reason, priv, err.Error())
			continue
		}
		for i := uint32(0); i < n; i++ {
			h := events[i]
			xmlStr, recID, evTime, rerr := renderEvent(h)
			if rerr == nil {
				key := c.channel + "|" + strconv.FormatInt(recID, 10)
				rec := model.CollectorRecord{
					Source: c.channel, SourceEventKey: key, EventTime: evTime,
					Kind: "winevent", XML: xmlStr,
				}
				if err := emit(rec); err == nil {
					c.mu.Lock()
					c.health.EventsSeen++
					c.health.LastSuccessAt = time.Now().UTC()
					c.health.Status = "available"
					c.mu.Unlock()
				}
				// Bookmark được tiến theo event cuối batch để lần chạy sau tiếp tục gần vị trí này.
				if bookmark != 0 {
					_, _, _ = procEvtUpdateBookmark.Call(uintptr(bookmark), uintptr(h))
				}
			}
			evtClose(h)
		}
		c.flushBookmark(bookmark)
	}
}

func (c *eventLogCollector) subscribe(bookmarkXML string) (sub evtHandle, bookmark evtHandle, signal windows.Handle, err error) {
	signal, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, 0, 0, err
	}
	ch, err := windows.UTF16PtrFromString(c.channel)
	if err != nil {
		windows.CloseHandle(signal)
		return 0, 0, 0, err
	}
	var q uintptr
	if c.query != "" {
		qp, qerr := windows.UTF16PtrFromString(c.query)
		if qerr != nil {
			windows.CloseHandle(signal)
			return 0, 0, 0, qerr
		}
		q = uintptr(unsafe.Pointer(qp))
	}
	flags := uintptr(evtSubscribeToFutureEvents)
	if bookmarkXML != "" {
		p, perr := windows.UTF16PtrFromString(bookmarkXML)
		if perr == nil {
			r, _, _ := procEvtCreateBookmark.Call(uintptr(unsafe.Pointer(p)))
			bookmark = evtHandle(r)
			if bookmark != 0 {
				flags = evtSubscribeStartAfterBookmark
			}
		}
	}
	r, _, callErr := procEvtSubscribe.Call(0, uintptr(signal), uintptr(unsafe.Pointer(ch)), q, uintptr(bookmark), 0, 0, flags)
	if r == 0 {
		if bookmark != 0 {
			evtClose(bookmark)
		}
		windows.CloseHandle(signal)
		if callErr != syscall.Errno(0) {
			return 0, 0, 0, callErr
		}
		return 0, 0, 0, windows.ERROR_INVALID_HANDLE
	}
	return evtHandle(r), bookmark, signal, nil
}

func (c *eventLogCollector) flushBookmark(bookmark evtHandle) {
	if bookmark == 0 || c.save == nil {
		return
	}
	buf := make([]uint16, 2048)
	var used uint32
	r, _, _ := procEvtRender.Call(0, uintptr(bookmark), evtRenderBookmark, uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), 0)
	if r == 0 && used > 0 {
		buf = make([]uint16, used/2+1)
		r, _, _ = procEvtRender.Call(0, uintptr(bookmark), evtRenderBookmark, uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), 0)
	}
	if r == 0 {
		return
	}
	_ = c.save(c.id, windows.UTF16ToString(buf), 0)
}

func renderEvent(h evtHandle) (xmlStr string, recordID int64, eventTime time.Time, err error) {
	var used uint32
	buf := make([]uint16, 32768)
	r, _, callErr := procEvtRender.Call(0, uintptr(h), evtRenderEventXML, uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), 0)
	if r == 0 {
		if used > uint32(len(buf)*2) {
			buf = make([]uint16, used/2+1)
			r, _, callErr = procEvtRender.Call(0, uintptr(h), evtRenderEventXML, uintptr(len(buf)*2), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), 0)
		}
		if r == 0 {
			if callErr != syscall.Errno(0) {
				return "", 0, time.Time{}, callErr
			}
			return "", 0, time.Time{}, windows.ERROR_INVALID_DATA
		}
	}
	xmlStr = windows.UTF16ToString(buf)
	var header struct {
		XMLName xml.Name `xml:"Event"`
		System  struct {
			TimeCreated struct {
				SystemTime string `xml:"SystemTime,attr"`
			} `xml:"TimeCreated"`
			EventRecordID string `xml:"EventRecordID"`
		} `xml:"System"`
	}
	_ = xml.Unmarshal([]byte(xmlStr), &header)
	recordID, _ = strconv.ParseInt(header.System.EventRecordID, 10, 64)
	eventTime, _ = time.Parse(time.RFC3339Nano, header.System.TimeCreated.SystemTime)
	if eventTime.IsZero() {
		eventTime, _ = time.Parse(time.RFC3339, header.System.TimeCreated.SystemTime)
	}
	return xmlStr, recordID, eventTime.UTC(), nil
}

func evtNext(sub evtHandle, events []evtHandle) (uint32, error) {
	var n uint32
	r, _, err := procEvtNext.Call(uintptr(sub), uintptr(len(events)), uintptr(unsafe.Pointer(&events[0])), 0, 0, uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		if err == windows.ERROR_NO_MORE_ITEMS || err == syscall.Errno(259) {
			return 0, err
		}
		if err != syscall.Errno(0) {
			return 0, err
		}
		return 0, windows.ERROR_NO_MORE_ITEMS
	}
	return n, nil
}

func evtClose(h evtHandle) {
	if h != 0 {
		_, _, _ = procEvtClose.Call(uintptr(h))
	}
}

func eventLogCollectors(cfg model.Config, load func(string) (string, int64, error), save func(string, string, int64) error) []Collector {
	out := make([]Collector, 0, len(cfg.Channels))
	for _, ch := range cfg.Channels {
		out = append(out, newEventLog(ch, load, save))
	}
	return out
}
