# Notices and provenance

No third-party source code or firmware is vendored in this repository. The live
bridge installs Wifit3 as a pinned external runtime dependency:

- Wifit3 `v0.1.5`, commit `e1f449c0248a8ad1d4080975ca0368d3f44d75d6`,
  copyright its respective contributors, GPL-2.0-only.

The local `c811` compatibility hooks record their upstream function and base
revision in source comments and in `upstream/wifit3.lock.json`. The review patch
`tools/mindrove_passive_scan/patches/wifit3-v0.1.5-c811-no-bt-coexist.patch`
is derived from Wifit3's GPL-2.0-only `chan.py` and retains that license.

Related reference work includes:

- Linux `rtw88`, copyright its respective contributors, with per-file SPDX terms;
- Realtek firmware, when and only when its applicable notice and redistribution terms have been verified.

Before importing a third-party file, record its source repository, immutable commit, original path, copyright notice, license, and any local modifications here and in the file header.

The Wifit3 RTL8821CU firmware is not copied into this repository because its
adjacent provenance is incomplete. It is obtained only through the pinned
external Wifit3 installation. Do not add a firmware blob merely because it is
publicly downloadable.
