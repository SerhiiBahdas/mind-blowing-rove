# SPDX-License-Identifier: GPL-2.0-only
"""Reviewed compatibility fixes for the immutable wifit3 dependency."""

from __future__ import annotations

import functools
import threading
from typing import Any, Callable


# Provenance:
#   upstream: https://github.com/derv82/wifit3
#   base: e1f449c0248a8ad1d4080975ca0368d3f44d75d6 (v0.1.5)
#   upstream path: src/wifit3/chips/rtl8821cu_dkms/chan.py:set_channel
#   repository patch: patches/wifit3-v0.1.5-c811-no-bt-coexist.patch
#
# A live 0bda:c811 EFUSE read reported bt_coexist=False. The pinned function
# unconditionally enters the BTC notifier on a band switch even though the
# bring-up code correctly skips btc.hal_init for that board, so the notifier
# dereferences missing t.btc state. The vendor-shaped fix is to call each BTC
# notifier only when info.bt_coexist is true.

_channel_patch_lock = threading.RLock()


def guard_btc_band_notifications(
    original_set_channel: Callable[..., Any],
    btc_module: Any,
) -> Callable[..., Any]:
    """Return the v0.1.5 channel setter with BTC callbacks gated by EFUSE.

    The temporary substitution keeps this repository from copying the rest of
    the upstream channel function. The lock makes the module-level substitution
    atomic if a caller introduces another tuning thread.
    """

    @functools.wraps(original_set_channel)
    def guarded(t: Any, info: Any, channel: int) -> Any:
        with _channel_patch_lock:
            if bool(info.bt_coexist):
                return original_set_channel(t, info, channel)

            notify_2g = btc_module.switchband_notify_2g
            notify_5g = btc_module.switchband_notify_5g
            btc_module.switchband_notify_2g = lambda _transport: None
            btc_module.switchband_notify_5g = lambda _transport: None
            try:
                return original_set_channel(t, info, channel)
            finally:
                btc_module.switchband_notify_2g = notify_2g
                btc_module.switchband_notify_5g = notify_5g

    guarded._mindrove_no_bt_coexist_fix = True  # type: ignore[attr-defined]
    return guarded


def apply_c811_no_bt_coexist_fix() -> None:
    """Install the reviewed compatibility fix into pinned wifit3 v0.1.5."""
    from wifit3.chips.rtl8821cu_dkms import btc, chan

    if getattr(chan.set_channel, "_mindrove_no_bt_coexist_fix", False):
        return
    chan.set_channel = guard_btc_band_notifications(chan.set_channel, btc)
