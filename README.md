# FyneWire

A cross-platform, modular desktop packet sniffer and analyzer written in Go, featuring a modern Fyne GUI, AI-powered filtering via Google Gemini, and high-speed packet decoding with gopacket.

---

## Features

* 🚦 **Live packet capture** from any local interface using libpcap (via cgo)
* 🖥️ **Native GUI** (Fyne) – fast, cross-platform, and beautiful
* 📋 **Protocol decoding** with [gopacket](https://github.com/google/gopacket) (Ethernet, IPv4/6, TCP, UDP, etc.)
* 🧠 **AI-powered filtering**: enter natural language prompts (“only DNS”, “TCP SYN floods”) and see only matching packets (via Google Gemini)
* 🔌 **Plugin architecture**: filter and enrich packets using the [Strategy](https://en.wikipedia.org/wiki/Strategy_pattern) and [Decorator](https://en.wikipedia.org/wiki/Decorator_pattern) patterns
* 🧪 **Unit and UI tests** – including headless Fyne test driver for CI
* 🤖 **GitHub Actions CI**: builds, vets, and tests on push

---

## Quickstart

### Prerequisites

* Go 1.21+ ([Install](https://go.dev/doc/install))
* libpcap development files (`sudo apt install libpcap-dev` or via Homebrew on macOS)
* For AI filtering: [Google Gemini API key](https://ai.google.dev/)
* C compiler (`gcc`, `clang`, or equivalent)

### Build & Run

```bash
git clone https://github.com/arya2004/fynewire.git
cd fynewire
make            # builds libsniffer.a and Go modules
make run        # launches the Fyne GUI
```

### Enabling AI Filtering

Set your Gemini API key as an environment variable:

```bash
export GEMINI_API_KEY="AIzaSy..."
```

---

## Design Overview

* **Multi-layered**: C only exposes raw capture; all parsing/logic is in Go.
* **Strategy pattern**: Swap filtering logic (pass-through, Gemini/AI, or custom code) at runtime.
* **Decorator pattern**: Enrich packets (GeoIP, TLS SNI, etc.) by stacking decorators with zero copy.
* **gopacket**: Efficient protocol parsing in pure Go.
* **Fyne**: Responsive, cross-platform UI. Data binding keeps lists live.
* **cgo**: Clean, minimal, and cross-platform for direct libpcap access.

---

## Testing & CI

* **Unit tests**: Run with `go test ./...`
* **GUI tests**: Headless mode via Fyne’s test driver.
* **Continuous Integration**: [GitHub Actions](.github/workflows/ci.yml) builds and tests on every push.

---

## Contributing

1. Fork and branch!
2. Run `make vet` and `go test ./...` before opening PRs.
3. For new features, keep C glue minimal; extend Go strategies or decorators.
4. For Gemini/AI features, be mindful of API quotas and errors.

---

## License

[MIT](LICENSE)


