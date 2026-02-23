# Speakeasy emulation image for bin-gate

Used when local Speakeasy fails (e.g. "fail to load the dynamic library" on Windows).

- **Build:** from project root run `bin-gate emulation-build`, or `docker build -t bin-gate-emulation:latest .` from this directory.
- **Auto:** with `BIN_GATE_EMULATION_DOCKER=1` (default), scan will try this image if local Speakeasy import fails.
