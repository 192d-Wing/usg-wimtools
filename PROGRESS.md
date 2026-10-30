# Project handoff

Last updated: 2026-10-30

## Goal

Build an independent pure-Rust Windows image tool, initially to prepare a
Windows 11 Pro image for a Dell OptiPlex D19U (QCM1250). The user requested
Rust 1.99, edition 2024, conventional commits, and signed commits.

## Current state

- Repository: this directory (`outputs/rust-image-tool`); branch `main`.
- Latest commit: `43fcb13 docs(servicing): define driver staging requirements`.
- README, validation log, and provenance document explain the current feature
  boundaries and prior checks. The Rust tool supports WIM inspection,
  extraction, experimental export/replacement, INF audits, package snapshots,
  catalog checks, and limited registry-hive inspection/editing.
- Driver injection/staging is **not implemented**. Do not copy driver files
  directly into DriverStore or claim the WIM is serviced.
- Exported experimental Windows 11 Pro WIM:
  `/Users/jwillman/Documents/Codex/2026-10-29/i-n/outputs/windows11-pro-experimental.wim`
- Dell QxM1250 JHY83 A07 package source:
  `/Users/jwillman/Downloads/QxM1250-JHY83_Win11_1.0_A07.exe`
- Extracted Dell package:
  `/Users/jwillman/Documents/Codex/2026-10-29/i-n/work/dell-drivers/QxM1250/Win11/x64`
- Windows ISO:
  `/Users/jwillman/Downloads/Windows11_Client_x64_en-us_26300_9457.iso`
- Dell inventory and earlier image/package reports are in the sibling
  `../` `outputs` directory (one level above this repository).

## Important findings

- D19U is associated with the QCM1250 regulatory model; Dell's QxM1250 driver
  pack is the model-family source, but contains configuration alternatives.
- The Rust scan found Intel VMD ID `PCI\VEN_8086&DEV_7D0B` in `iaStorVD.inf`.
  This ID is illustrative and has not been read from the actual target PC.
- The image is x64 Windows 11 Pro client build 26300. Limited audit checks pass.
- Existing audits do not establish the target's actual hardware IDs, BIOS
  storage mode, Windows Setup behavior, or installed-driver state.
- No Windows VM or servicing-generated package fixture is in the workspace.
  Host is Apple Silicon macOS, with QEMU installed and about 70 GiB free at
  last check. The Windows ISO is 8.4 GiB; installing a VM was not attempted.
- The ISO mount attempt failed in this environment. Neither `dism` nor
  `wimlib-imagex` is installed here.

## Next work

1. On a Windows machine or VM, create a disposable offline Windows image and
   use Microsoft's DISM/SetupAPI servicing flow to add one Dell package.
2. Capture before/after WIM, mounted file tree, relevant registry hives/keys,
   package identity, command output, and hashes. Record Windows version and
   servicing command/version. Do not use a production image for this fixture.
3. Add a fixture-generation guide/script and a compact, redistributable fixture
   manifest to this repo; avoid committing proprietary driver binaries unless
   redistribution is confirmed.
4. Implement a Rust fixture analyzer and compare each observed file/registry
   delta. Only then design and implement package staging; service install.wim
   and boot.wim separately and validate on Windows.

## Build and checks

Run from this repository:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release --locked
```

At the latest edit, `cargo fmt --check`, `git diff --check`, and release build
passed. Tests and Clippy were not rerun for the documentation-only change.

## Signing note

Git is configured for SSH commit signing through the 1Password SSH agent. In
the prior Codex process, 1Password's app was open, but access to its configured
socket under `~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock`
failed with `Operation not permitted`; signing failed. The user then committed
the staged change. `git log --show-signature` currently complains that
`gpg.ssh.allowedSignersFile` is not configured, so local verification of that
commit's signature is not set up. Do not change the user's signing config
without need; test agent access in the new machine/session.

