package ui

import (
	"fmt"
	"image/color"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/arya2004/fynewire/internal/ai"
	"github.com/arya2004/fynewire/internal/model"
	"github.com/arya2004/fynewire/internal/sniffer"
)

type App struct {
	mu   sync.Mutex
	chat ai.Chat

	win                               fyne.Window
	ifSel                              *widget.Select
	list                               *widget.List
	detail, aiBox                      *widget.Entry
	status                             *canvas.Text
	startBtn, stopBtn                  *widget.Button
	packets                            []model.Packet
	curSniffer                         sniffer.Sniffer
}

func NewApp(chat ai.Chat) *App { return &App{chat: chat} }

func (u *App) Run(ifaces []string) {
	a := app.New()
	a.Settings().SetTheme(&bigTheme{base: fyne.CurrentApp().Settings().Theme()})
	w := a.NewWindow("Packet-Tracer + Gemini")
	w.Resize(fyne.NewSize(1920, 1080))
	w.CenterOnScreen()
	w.SetMaster()
	u.win = w

	u.makeUI()
	u.ifSel.Options = append([]string{}, ifaces...)
	if len(ifaces) > 0 {
		u.ifSel.SetSelected(ifaces[0])
	}
	w.ShowAndRun()
}

func (u *App) makeUI() {
	// top bar
	u.ifSel = widget.NewSelect([]string{"loading…"}, nil)
	u.startBtn = widget.NewButtonWithIcon("Start", theme.MediaPlayIcon(), u.startCap)
	u.stopBtn = widget.NewButtonWithIcon("Stop", theme.MediaStopIcon(), u.stopCap)
	u.stopBtn.Disable()
	u.status = canvas.NewText("", color.Gray{Y: 0x88})

	top := container.NewHBox(
		widget.NewLabelWithStyle("Interface:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		u.ifSel, u.startBtn, u.stopBtn)

	// centre
	u.list = widget.NewList(
		func() int {
			u.mu.Lock()
			defer u.mu.Unlock()
			return len(u.packets)
		},
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.ListItemID, o fyne.CanvasObject) {
			u.mu.Lock()
			o.(*widget.Label).SetText(u.packets[i].Summary)
			u.mu.Unlock()
		},
	)

	u.detail = widget.NewMultiLineEntry()
	u.detail.Wrapping = fyne.TextWrapWord

	u.list.OnSelected = func(id widget.ListItemID) {
		u.mu.Lock()
		txt := u.packets[id].Detail
		u.mu.Unlock()
		u.detail.SetText(txt)
	}

	split := container.NewHSplit(u.list, container.NewScroll(u.detail))
	split.Offset = 0.35

	// chat box
	u.aiBox = widget.NewMultiLineEntry()
	u.aiBox.SetMinRowsVisible(4)
	u.aiBox.SetPlaceHolder(`Ask (e.g. “show udp from port 53”)`)
	send := widget.NewButtonWithIcon("", theme.NavigateNextIcon(), u.applyAI)
	send.Importance = widget.HighImportance

	bottom := container.NewBorder(nil, nil, nil, send, u.aiBox)

	u.win.SetContent(container.NewBorder(container.NewVBox(top, u.status), bottom, nil, nil, split))
}

func (u *App) startCap() {
	dev := u.ifSel.Selected
	s := sniffer.New(dev)
	if err := s.Start(); err != nil {
		u.status.Text = err.Error()
		u.status.Refresh()
		return
	}
	u.curSniffer = s
	u.packets = nil
	u.startBtn.Disable()
	u.ifSel.Disable()
	u.stopBtn.Enable()
	u.status.Text = "Capturing…"
	u.status.Refresh()

	go func() {
		for p := range s.Packets() {
			u.mu.Lock()
			u.packets = append(u.packets, p)
			u.mu.Unlock()
			fyne.Do(func() { u.list.Refresh() })
		}
	}()
}

func (u *App) stopCap() {
	if u.curSniffer != nil {
		u.curSniffer.Stop()
		u.curSniffer = nil
	}
	u.startBtn.Enable()
	u.ifSel.Enable()
	u.stopBtn.Disable()
	u.status.Text = "Stopped"
	u.status.Refresh()
}

func (u *App) applyAI() {
	q := u.aiBox.Text
	if q == "" {
		return
	}
	u.status.Text = "Contacting Gemini…"
	u.status.Refresh()

	u.mu.Lock()
	snapshot := append([]model.Packet(nil), u.packets...)
	u.mu.Unlock()

	go func() {
		filtered, err := u.chat.Reply(q, snapshot)
		fyne.Do(func() {
			if err != nil {
				u.status.Text = err.Error()
			} else if len(filtered) == 0 {
				u.status.Text = "No packets matched."
			} else {
				u.mu.Lock()
				u.packets = filtered
				u.mu.Unlock()
				u.list.Refresh()
				u.status.Text = fmt.Sprintf("Filtered to %d packets.",len(filtered))
			}
			u.status.Refresh()
		})
	}()
}
