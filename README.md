# qiui-server
A QiUi local server for cages.

Rust port of the Python KeyPod scripts (cloud command generation via the QIUI
Open Platform API + local BLE via btleplug). See RESEARCH notes for protocol details.

```
# .qiui_pod_env (gitignored) must contain QIUI_CLIENT_ID=...
cargo run -- identify
cargo run -- status --debug
cargo run -- unlock
cargo run -- lock
```
Needs BlueZ + libdbus dev headers on Linux.
