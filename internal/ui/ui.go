package ui

import (
	"log"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/widget"
	"github.com/arya2004/fynewire/internal/capture"
)


func Launch() {

	a := app.New()
	w := a.NewWindow("FyneWire")

	//interface
	devs, err := capture.Interfaces()
	if err != nil || len(devs) == 0 {
		log.Fatalf("no capture devs found: %v", err)

	}

	current := binding.NewString()
	current.Set(devs[0])

	selectDev := widget.NewSelect(devs, func(s string) {
		current.Set(s)
	})
	selectDev.SetSelected(devs[0])


	//pkt list
	pktData := binding.NewStringList()
	list := widget.NewListWithData(pktData,
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(di binding.DataItem, co fyne.CanvasObject) {
			co.(*widget.Label).Bind(di.(binding.String))
		})

	start := widget.NewButton("Start Capture", func(){

		dev, _ := current.Get()
		pkts, err := capture.Start(dev)
		if err != nil {
			log.Println(err)
			return
		}
		go func() {

			for p := range pkts {
				fyne.Do(func() {
					pktData.Append(p.Summary)
				})
			}

		}()

	})

	w.SetContent(container.NewBorder(selectDev, start, nil, nil, list))
	w.Resize(fyne.NewSize(700, 500))

	w.ShowAndRun()





}