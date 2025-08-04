package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
)

type bigTheme struct{ base fyne.Theme }

func (b *bigTheme) Color(n fyne.ThemeColorName, v fyne.ThemeVariant) color.Color {
	return b.base.Color(n, v)
}
func (b *bigTheme) Font(s fyne.TextStyle) fyne.Resource { return b.base.Font(s) }
func (b *bigTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return b.base.Icon(n) }
func (b *bigTheme) Size(n fyne.ThemeSizeName) float32       { return b.base.Size(n) * 1.5 }
