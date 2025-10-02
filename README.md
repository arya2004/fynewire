# FyneWire

A cross-platform, modular desktop packet sniffer and analyzer written in Go, featuring a modern Fyne GUI, AI-powered filtering via Google Gemini, and high-speed packet decoding with gopacket.
Features

🚦 **Live packet capture** from any local interface using libpcap (via cgo)
🖥️ **Native GUI** (Fyne) – fast, cross-platform, and beautiful
📋 **Protocol decoding** with `gopacket` (Ethernet, IPv4/6, TCP, UDP, etc.)
🧠 **AI-powered filtering**: enter natural language prompts (“only DNS”, “TCP SYN floods”) and see only matching packets (via Google Gemini)
🔌 **Plugin architecture**: filter and enrich packets using the `Strategy` and `Decorator` patterns
🧪 **Unit and UI tests** – including headless Fyne test driver for CI
🤖 **GitHub Actions CI**: builds, vets, and tests on push

---
## Building and Running

### Prerequisites

You will need the following installed to build and run FyneWire:

* **Go 1.21+**: Download from [golang.org](https://golang.org/).
* **A C Compiler**: Such as GCC, Clang, or the Xcode Command Line Tools.
    * On macOS: `xcode-select --install`
    * On Debian/Ubuntu: `sudo apt-get install build-essential`
* **`libpcap` Development Libraries**: This is required for packet capture.
    * On macOS: `brew install libpcap`
    * On Debian/Ubuntu: `sudo apt-get install libpcap-dev`
    * On Fedora/RHEL: `sudo dnf install libpcap-devel`
* **Google Gemini API Key** (Optional): Required only for the AI filtering feature. You can get a key from [Google AI Studio](https://aistudio.google.com/).

### Installation and Execution

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/arya2004/fynewire.git](https://github.com/arya2004/fynewire.git)
    cd fynewire
    ```

2.  **Build the application:**
    The `make` command compiles the required C library and builds the Go application.
    ```bash
    make
    ```

3.  **Run the application:**
    Packet sniffing requires elevated privileges.
    ```bash
    sudo ./fynewire
    ```
    
    * To use the **AI filtering features**, you must set your API key as an environment variable first. Use the `-E` flag with `sudo` to preserve the variable.
        ```bash
        export GEMINI_API_KEY="your-api-key"
        sudo -E ./fynewire
        ```

---
## Design Overview

* **Multi-layered**: C only exposes raw capture; all parsing/logic is in Go.
* **Strategy pattern**: Swap filtering logic (pass-through, Gemini/AI, or custom code) at runtime.
* **Decorator pattern**: Enrich packets (GeoIP, TLS SNI, etc.) by stacking decorators with zero copy.
* **gopacket**: Efficient protocol parsing in pure Go.
* **Fyne**: Responsive, cross-platform UI. Data binding keeps lists live.
* **cgo**: Clean, minimal, and cross-platform for direct libpcap access.

## Testing & CI

* **Unit tests**: Run with `go test ./...`
* **GUI tests**: Headless mode via Fyne’s test driver.
* **Continuous Integration**: `GitHub Actions` builds and tests on every push.

## Contributing

* Fork and branch!
* Run `make vet` and `go test ./...` before opening PRs.
* For new features, keep C glue minimal; extend Go strategies or decorators.
* For Gemini/AI features, be mindful of API quotas and errors.

## License

MIT