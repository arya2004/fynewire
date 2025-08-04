
# Contributing to FyneWire

First, thanks for your interest! 🫱‍🫲
FyneWire welcomes new features, plugins, and bugfixes from everyone—especially if you care about networking, UI, or applied AI.

---

## How to contribute

1. **Fork** this repository and create a new branch for your changes.
2. Write clear, modular Go code—prefer interfaces and clean package structure.
3. If touching C, keep the glue code as minimal and portable as possible.
4. Add or update **tests** for your code (`go test ./...`).
5. Before you submit, run:

   ```bash
   make vet
   go test ./...
   ```
6. Open a **Pull Request** with a clear description.
   If you add a feature, demo it in screenshots/gifs if possible!

---

## Coding style

* **Go**:

  * Use `gofmt` and idiomatic error handling.
  * Favor interfaces and the [Strategy](https://en.wikipedia.org/wiki/Strategy_pattern) / [Decorator](https://en.wikipedia.org/wiki/Decorator_pattern) patterns for pluggable features.
  * Avoid global state unless absolutely necessary (the UI uses app-wide singletons only for windows/theming).
* **C (libpcap glue)**:

  * Make changes only if you’re fixing bugs or adding core protocol support.
  * Don’t bake filtering or decoding logic into C—leave that to Go.
* **UI**:

  * Use [Fyne](https://fyne.io/) idioms.
  * Keep the UI reactive; refresh widgets on data/model changes.

---

## Adding features

* **New filters**: Implement as Go strategies or decorators—see `internal/ai` and `internal/model`.
* **Gemini/AI**:

  * Use the [Google generative-ai-go SDK](https://pkg.go.dev/github.com/google/generative-ai-go/genai).
  * Handle all errors and show clear UI feedback.
  * Be mindful of API quotas—use your own key for dev/testing.
* **Plugins**:

  * Place protocol/enricher plugins in the `internal/plugins/` folder (or propose a new subpackage).

---

## Building and running

* **Install Go 1.21+**
* **Get system deps** (`libpcap-dev`, X11/OpenGL dev packages for Linux, Homebrew/Xcode for macOS)
* **Build** with:

  ```bash
  make
  ```
* **Run** with:

  ```bash
  make run
  ```
* **AI**: Set your Gemini API key in the GUI (top bar), or via environment:

  ```bash
  export GEMINI_API_KEY=...
  ```

---

## Tests & CI

* **Unit tests**:

  ```bash
  go test ./...
  ```
* **Fyne GUI tests**:
  Headless testing via Fyne’s testdriver.
* **CI**:
  PRs are built & tested by [GitHub Actions](.github/workflows/release.yml).

---

## Questions? Ideas? Bugs?

* Open an [Issue](https://github.com/arya2004/fynewire/issues) with steps to reproduce or your proposal.
* For general Go, Fyne, or pcap issues, please link to docs or reference code where possible.

---

## License

By contributing, you agree your code will be MIT-licensed as per [LICENSE](LICENSE).

---

**Happy hacking!** 🚦🧠🖥️
