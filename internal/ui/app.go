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
	"github.com/arya2004/fynewire/internal/filter"
	"github.com/arya2004/fynewire/internal/model"
	"github.com/arya2004/fynewire/internal/sniffer"
)

type App struct {
	mu   sync.Mutex
	chat ai.Chat // may be nil until key set

	win                          fyne.Window
	ifSel                        *widget.Select
	list                         *widget.List
	detail, aiBox                *widget.Entry
	status                       *canvas.Text
	startBtn, stopBtn, setKeyBtn *widget.Button
	keyEntry                     *widget.Entry
	packets                      []model.Packet
	allPackets                   []model.Packet // Store original unfiltered packets
	curSniffer                   sniffer.Sniffer

	// Filter input fields
	filterProtocol, filterSrcIP, filterDstIP     *widget.Entry
	filterSrcPort, filterDstPort, filterFreeText *widget.Entry
}

func NewApp() *App { return &App{} }

func (u *App) Run(ifaces []string) {
	a := app.New()
	a.Settings().SetTheme(&bigTheme{base: fyne.CurrentApp().Settings().Theme()})

	u.win = a.NewWindow("Packet-Tracer + Gemini")
	u.win.Resize(fyne.NewSize(1920, 1080))
	u.win.CenterOnScreen()
	u.win.SetMaster()

	u.buildUI(ifaces)
	u.win.ShowAndRun()
}

func (u *App) buildUI(ifaces []string) {
	//top
	u.ifSel = widget.NewSelect(ifaces, nil)
	u.startBtn = widget.NewButtonWithIcon("Start", theme.MediaPlayIcon(), u.startCap)
	u.stopBtn = widget.NewButtonWithIcon("Stop", theme.MediaStopIcon(), u.stopCap)
	u.stopBtn.Disable()

	u.keyEntry = widget.NewPasswordEntry()
	u.keyEntry.SetPlaceHolder("Gemini API key")
	u.setKeyBtn = widget.NewButton("Set Key", u.saveAPIKey)

	u.status = canvas.NewText("", color.Gray{Y: 0x88})

	top := container.NewHBox(
		widget.NewLabelWithStyle("Interface:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		u.ifSel, u.startBtn, u.stopBtn,
		canvas.NewText("  |  ", color.Gray{Y: 0x66}),
		u.keyEntry, u.setKeyBtn,
	)

	// Filter section
	u.filterProtocol = widget.NewEntry()
	u.filterProtocol.SetPlaceHolder("Protocol (e.g., TCP, UDP)")
	u.filterProtocol.OnChanged = func(string) { u.applyFilters() }

	u.filterSrcIP = widget.NewEntry()
	u.filterSrcIP.SetPlaceHolder("Source IP")
	u.filterSrcIP.OnChanged = func(string) { u.applyFilters() }

	u.filterDstIP = widget.NewEntry()
	u.filterDstIP.SetPlaceHolder("Destination IP")
	u.filterDstIP.OnChanged = func(string) { u.applyFilters() }

	u.filterSrcPort = widget.NewEntry()
	u.filterSrcPort.SetPlaceHolder("Source Port")
	u.filterSrcPort.OnChanged = func(string) { u.applyFilters() }

	u.filterDstPort = widget.NewEntry()
	u.filterDstPort.SetPlaceHolder("Destination Port")
	u.filterDstPort.OnChanged = func(string) { u.applyFilters() }

	u.filterFreeText = widget.NewEntry()
	u.filterFreeText.SetPlaceHolder("Free text search")
	u.filterFreeText.OnChanged = func(string) { u.applyFilters() }

	clear := widget.NewButton("Clear", func() {
		u.filterProtocol.SetText("")
		u.filterSrcIP.SetText("")
		u.filterDstIP.SetText("")
		u.filterSrcPort.SetText("")
		u.filterDstPort.SetText("")
		u.filterFreeText.SetText("")
		u.applyFilters()
	})

	filterRow1 := container.NewHBox(
		widget.NewLabel("Protocol:"), u.filterProtocol,
		widget.NewLabel("Src IP:"), u.filterSrcIP,
		widget.NewLabel("Dst IP:"), u.filterDstIP,
	)

	filterRow2 := container.NewHBox(
		widget.NewLabel("Src Port:"), u.filterSrcPort,
		widget.NewLabel("Dst Port:"), u.filterDstPort,
		widget.NewLabel("Free Text:"), u.filterFreeText,
		clear,
	)

	filters := container.NewVBox(
		widget.NewLabelWithStyle("Filters:", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		filterRow1,
		filterRow2,
	)

	//center
	u.list = widget.NewList(u.rowCount,
		func() fyne.CanvasObject { return widget.NewLabel("") },
		u.updateRow,
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

	//chat box
	u.aiBox = widget.NewMultiLineEntry()
	u.aiBox.SetMinRowsVisible(4)
	u.aiBox.SetPlaceHolder(`Ask (e.g. “show udp from port 53”)`)
	send := widget.NewButtonWithIcon("", theme.NavigateNextIcon(), u.applyAI)
	send.Importance = widget.HighImportance

	bottom := container.NewBorder(nil, nil, nil, send, u.aiBox)

	//root
	u.win.SetContent(container.NewBorder(container.NewVBox(top, u.status, filters),
		bottom, nil, nil, split))
}

func (u *App) saveAPIKey() {
	key := u.keyEntry.Text
	if key == "" {
		u.setStatus("Please enter an API key.")
		return
	}
	u.chat = ai.NewGemini(key)
	u.keyEntry.SetText("") // Clear the API key field after successful setting
	u.setStatus("API key saved – ready!")
}

func (u *App) setStatus(s string) {
	u.status.Text = s
	u.status.Refresh()
}

func (u *App) rowCount() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.packets)
}
func (u *App) updateRow(i widget.ListItemID, o fyne.CanvasObject) {
	u.mu.Lock()
	o.(*widget.Label).SetText(u.packets[i].Summary)
	u.mu.Unlock()
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
	u.allPackets = nil
	u.startBtn.Disable()
	u.ifSel.Disable()
	u.stopBtn.Enable()
	u.status.Text = "Capturing…"
	u.status.Refresh()

	go func() {
		for p := range s.Packets() {
			u.mu.Lock()
			u.allPackets = append(u.allPackets, p)
			u.mu.Unlock()
			fyne.Do(func() { u.applyFilters() })
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

func (u *App) applyFilters() {
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.allPackets == nil {
		return
	}

	// Get filter values
	proto := u.filterProtocol.Text
	srcIP := u.filterSrcIP.Text
	dstIP := u.filterDstIP.Text
	srcPort := u.filterSrcPort.Text
	dstPort := u.filterDstPort.Text
	freeText := u.filterFreeText.Text

	// Apply filters using the filter package
	u.packets = filter.Apply(u.allPackets, proto, srcIP, dstIP, srcPort, dstPort, freeText, 0)

	// Refresh the list
	u.list.Refresh()

	// Update status
	totalPackets := len(u.allPackets)
	filteredPackets := len(u.packets)
	if totalPackets == filteredPackets {
		u.setStatus(fmt.Sprintf("Showing %d packets", totalPackets))
	} else {
		u.setStatus(fmt.Sprintf("Showing %d of %d packets", filteredPackets, totalPackets))
	}
}

func (u *App) applyAI() {
	if u.chat == nil {
		u.setStatus("Set your Gemini API key first.")
		return
	}
	q := u.aiBox.Text
	if q == "" {
		return
	}
	u.setStatus("Contacting Gemini…")

	go func() {

		// take a snapshot safely

		u.mu.Lock()
		snapshot := append([]model.Packet(nil), u.packets...)
		u.mu.Unlock()

		// do long operation without holding lock

		filtered, err := u.chat.Reply(q, snapshot)

		// now update the UI

		fyne.Do(func() {
			if err != nil {
				u.setStatus(err.Error())
				return
			}

			// checking length
			if len(filtered) == 0 {
				u.setStatus("No packets matched.")
				return
			}

			// update the data under lock
			u.mu.Lock()
			u.packets = filtered
			u.mu.Unlock()

			// updating the UI widgets (no lock held here)

			u.list.Refresh()
			u.setStatus(fmt.Sprintf("Filtered to %d packets.", len(filtered)))

		})
	}()
}
