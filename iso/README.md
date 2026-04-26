# Bootable ISO (stretch goal — not built in v0)

Per decision **D-008**, v0 ships as a Vagrant box. A bootable ISO is
deferred. This directory holds the future `live-build` configuration.

## Sketch

The plan when we get to it:

1. Start from `ubuntu-24.04-server-amd64` and `live-build` config.
2. Add an APT preseed that installs `agentsandbox.deb` (we'll need
   to build a `.deb` from `make install` first — straightforward
   `dh_make`).
3. Enable the `agentsandbox.service` systemd unit by default.
4. Add a first-boot script that opens `http://127.0.0.1:9000/ui/`
   in Firefox so the user lands on the policy editor.
5. Sign the ISO. (TBD: which key.)

## Why not now

- `live-build` is a multi-hour CI pipeline.
- ISO signing requires a key-management decision we have not made.
- Until the runtime API is stable, every change would re-trigger an
  ISO rebuild — wasteful.

When we do start: see `vendor/tetragon/Documentation/` for examples
of packaging eBPF artifacts in distro images.
