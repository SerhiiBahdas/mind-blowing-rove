# Contributing

Thank you for helping make the MindRove adapter useful on modern Macs.

## Useful reports

Build the probe and attach its JSON output to an issue:

```sh
make build
./build/mindrove-usb-probe --json
```

If comfortable, include the Apple-silicon generation, macOS major version, hub
make/model, and whether the adapter appears in System Information under USB.
Exact host-model and minor-version details are optional.

## Privacy

Before uploading logs or captures, check them for:

- usernames and home-directory paths;
- Wi-Fi network names and credentials;
- IP and MAC addresses unrelated to the MindRove link;
- device serial numbers;
- unrelated USB devices.

The included probe omits these fields by design. Raw `ioreg`, `system_profiler`, and packet-capture output can contain more information than expected.

Raw sensor logs, packet captures, screenshots, `.env` files, and common private
key formats are ignored by this repository. Do not bypass those rules with
`git add --force`. Replace real SSIDs, BSSIDs, station MACs, usernames, local
paths, and recording timestamps with explicit placeholders in examples.

Git commit author names and email addresses become public repository metadata.
Use a suitable display name and a provider's no-reply email address if you do
not want a personal email exposed.

Push only the intended named branch. Do not mirror-push or copy a developer's
local `.git` directory, because local recovery refs and unreachable objects are
not part of the project and can retain discarded diagnostic data.

## Development principles

- Keep System Integrity Protection and other macOS security features enabled.
- Prefer documented DriverKit APIs over legacy kernel extensions.
- Document the origin and license of ported code and firmware.
- Never commit vendor firmware until its redistribution terms are verified.
- Keep chipset transport code separate from macOS integration code so it can be tested outside a signed system extension.
