# Installing cy-tls

cy-tls ships signed releases for macOS, Linux, and Windows. Every
release publishes 5 binaries with predictable names so you can script
against them.

## Recommended

### macOS / Linux — Homebrew

```sh
brew install cybrium-ai/cli/cy-tls
```

The formula lives at
[`cybrium-ai/homebrew-cli`](https://github.com/cybrium-ai/homebrew-cli)
and auto-updates on every release.

### Windows — Scoop

```powershell
scoop bucket add cybrium-ai https://github.com/cybrium-ai/scoop-bucket
scoop install cybrium-ai/cy-tls
```

The manifest is auto-updated by the release pipeline. The Windows
binary is signed via Azure Trusted Signing — your SmartScreen won't
complain.

### Any platform — Cargo

```sh
cargo install --git https://github.com/cybrium-ai/cy-tls
```

Builds from source; needs a working Rust 1.75+ toolchain.

## Direct download

Each tagged release publishes 5 binaries to
[`/releases`](https://github.com/cybrium-ai/cy-tls/releases). Naming is
predictable:

| Triple | Filename |
|--------|----------|
| Linux x86_64 | `cy-tls-linux-amd64` |
| Linux ARM64  | `cy-tls-linux-arm64` |
| macOS Intel  | `cy-tls-darwin-amd64` |
| macOS ARM    | `cy-tls-darwin-arm64` |
| Windows x64  | `cy-tls-windows-amd64.exe` |

```sh
# Example: install the macOS ARM binary by hand
curl -L -o cy-tls https://github.com/cybrium-ai/cy-tls/releases/latest/download/cy-tls-darwin-arm64
chmod +x cy-tls
sudo mv cy-tls /usr/local/bin/
cy-tls --version
```

## Signature verification

### Windows (Authenticode)

```powershell
Get-AuthenticodeSignature .\cy-tls-windows-amd64.exe
```

You should see `Status: Valid` and a signer subject containing
`Cybrium`.

### macOS (Developer ID + notarization)

Once the Apple Org-account Developer ID lands (currently in conversion
from a personal account), the macOS binaries will be signed and
notarized. Verify with:

```sh
codesign --verify --verbose=2 cy-tls
spctl --assess --verbose cy-tls
```

Until then, macOS binaries are unsigned. Bypass Gatekeeper with
right-click → Open or:

```sh
xattr -d com.apple.quarantine cy-tls
```

### Linux (SHA256)

Every release artifact has an attached `*.sha256` you can verify:

```sh
sha256sum -c cy-tls-linux-amd64.sha256
```

## Build from source

```sh
git clone https://github.com/cybrium-ai/cy-tls
cd cy-tls
cargo build --release
./target/release/cy-tls --version
```

Requires Rust 1.75+. Reproducible builds are not yet guaranteed (planned
for v1.0.0).

## Where the binary expects to live

| Platform | Recommended path |
|----------|------------------|
| macOS    | `/opt/homebrew/bin/cy-tls` or `/usr/local/bin/cy-tls` |
| Linux    | `/usr/local/bin/cy-tls` or `~/.local/bin/cy-tls` |
| Windows  | `%LOCALAPPDATA%\scoop\apps\cy-tls\current\cy-tls.exe` (Scoop) or anywhere on `%PATH%` |

The platform-side
[`cytls_runner.py`](https://github.com/cybrium-ai/cybrium/blob/main/backend/tools_runtime/cytls_runner.py)
uses `which cy-tls` to locate the binary — any of the above paths work.
