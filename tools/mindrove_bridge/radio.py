# SPDX-License-Identifier: GPL-2.0-only
"""Narrow wifit3 RTL8821CU adapter and target-filtered async RX queue."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import functools
import inspect
import threading
import time
from typing import Any, Awaitable, Callable, Optional, Protocol, Union

from mindrove_station.common import mac_bytes


USB_VENDOR_ID = 0x0BDA
USB_PRODUCT_ID = 0xC811
WIFIT3_VERSION = "0.1.5"
WIFIT3_COMMIT = "e1f449c0248a8ad1d4080975ca0368d3f44d75d6"
RF18_BAND_5GHZ = 1 << 16
RECOVERY_CHANNEL_5GHZ = 36


class RadioError(RuntimeError):
    """Base error for the user-space radio boundary."""


class AdapterNotFoundError(RadioError):
    """The exact 0bda:c811 adapter could not be selected unambiguously."""


class TuneError(RadioError):
    """A fixed-channel tune did not survive RF register readback."""


class RadioDriver(Protocol):
    """The wifit3 surface consumed by this bridge (also easy to fake)."""

    info: Any

    def register_rx_callback(self, callback: Callable[[Any], None]) -> None: ...

    def register_disconnect_callback(self, callback: Callable[[Exception], None]) -> None: ...

    async def connect(self) -> bool: ...

    async def set_channel(self, channel: int, scan: bool = False) -> bool: ...

    async def enter_active_monitor(self, mac: bytes, bssid: Optional[bytes] = None) -> bytes: ...

    async def exit_active_monitor(self) -> None: ...

    async def inject_frame(self, frame: bytes) -> bool: ...

    async def close(self) -> None: ...


@dataclass(frozen=True)
class ReceivedFrame:
    raw: bytes
    received_at: float
    parsed: Any = None


class _Disconnected:
    def __init__(self, error: Exception):
        self.error = error


class TargetFrameQueue:
    """Bounded queue containing only frames from one AP to our station/group.

    wifit3 currently dispatches on the event-loop thread, but this callback also
    works if a future reader invokes it on a worker thread.
    """

    def __init__(
        self,
        bssid: bytes,
        station_mac: bytes,
        *,
        maxsize: int = 256,
        allow_group: bool = True,
    ) -> None:
        if maxsize <= 0:
            raise ValueError("RX queue size must be positive")
        self.bssid = mac_bytes(bssid)
        self.station_mac = mac_bytes(station_mac)
        self.allow_group = allow_group
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._loop = asyncio.get_running_loop()
        self._closed = False
        self.dropped = 0

    def _matches(self, raw: bytes) -> bool:
        if len(raw) < 16:
            return False
        receiver = raw[4:10]
        transmitter = raw[10:16]
        receiver_ok = receiver == self.station_mac
        if self.allow_group and receiver and receiver[0] & 1:
            receiver_ok = True
        return receiver_ok and transmitter == self.bssid

    def packet_callback(self, packet: Any) -> None:
        if self._closed:
            return
        raw = getattr(packet, "raw", None)
        if raw is None:
            return
        raw_bytes = bytes(raw)
        if not self._matches(raw_bytes):
            return
        item = ReceivedFrame(raw_bytes, time.monotonic(), packet)
        self._loop.call_soon_threadsafe(self._put, item)

    def disconnect_callback(self, error: Exception) -> None:
        if not self._closed:
            self._loop.call_soon_threadsafe(self._put, _Disconnected(error))

    def _put(self, item: Any) -> None:
        if self._closed:
            return
        if self._queue.full():
            try:
                self._queue.get_nowait()
                self.dropped += 1
            except asyncio.QueueEmpty:
                pass
        self._queue.put_nowait(item)

    async def receive(self, timeout: Optional[float] = None) -> ReceivedFrame:
        try:
            if timeout is None:
                item = await self._queue.get()
            else:
                item = await asyncio.wait_for(self._queue.get(), timeout)
        except asyncio.TimeoutError as exc:
            raise TimeoutError("timed out waiting for a target frame") from exc
        if isinstance(item, _Disconnected):
            raise RadioError("adapter disconnected") from item.error
        return item

    def drain(self) -> None:
        while True:
            try:
                self._queue.get_nowait()
            except asyncio.QueueEmpty:
                break

    def close(self) -> None:
        self._closed = True
        self.drain()


@dataclass(frozen=True)
class TuneRetry:
    channel: int
    attempt: int
    max_attempts: int
    rf18: int


RF18Reader = Callable[[RadioDriver], Union[int, Awaitable[int]]]
FixedTune = Callable[[RadioDriver, int], Union[int, Awaitable[int]]]
TuneRetryHook = Callable[[RadioDriver, TuneRetry], Union[None, Awaitable[None]]]
CompatibilityHook = Callable[[], None]


_compatibility_lock = threading.RLock()


def guard_no_bt_coexist_set_channel(
    original: Callable[..., Any], btc_module: Any
) -> Callable[..., Any]:
    """Gate v0.1.5 BTC notifications when EFUSE says no BT coexistence.

    The pinned channel function otherwise dereferences ``transport.btc`` even
    though bring-up correctly omits that state for the MindRove c811 board.
    """

    @functools.wraps(original)
    def guarded(transport: Any, info: Any, channel: int) -> Any:
        with _compatibility_lock:
            if bool(info.bt_coexist):
                return original(transport, info, channel)
            notify_2g = btc_module.switchband_notify_2g
            notify_5g = btc_module.switchband_notify_5g
            btc_module.switchband_notify_2g = lambda _transport: None
            btc_module.switchband_notify_5g = lambda _transport: None
            try:
                return original(transport, info, channel)
            finally:
                btc_module.switchband_notify_2g = notify_2g
                btc_module.switchband_notify_5g = notify_5g

    guarded._mindrove_c811_no_bt_fix = True  # type: ignore[attr-defined]
    return guarded


def install_no_bt_coexist_compatibility() -> None:
    """Install the narrowly reviewed compatibility hook in pinned wifit3."""
    from wifit3.chips.rtl8821cu_dkms import btc, chan

    if getattr(chan.set_channel, "_mindrove_c811_no_bt_fix", False):
        return
    chan.set_channel = guard_no_bt_coexist_set_channel(chan.set_channel, btc)


def rf18_confirms_2g_channel(rf18: int, channel: int) -> bool:
    """Require a 2.4-GHz band bit and the requested channel in RF register 18."""
    return not bool(rf18 & RF18_BAND_5GHZ) and (rf18 & 0xFF) == channel


async def _possibly_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def _default_retry_hook(driver: RadioDriver, _event: TuneRetry) -> None:
    # wifit3's full band switch is guarded by current_band. Invalidating the
    # latch makes the next deliberate tune repeat it, which is the proven RF18
    # recovery path rather than simply clearing one RF bit.
    transport = getattr(driver, "transport", None)
    if transport is None:
        raise TuneError("driver has no transport for a full-band retune")
    transport.current_band = None
    transport._mindrove_force_band_bounce = True


async def _read_wifit3_rf18(driver: RadioDriver) -> int:
    """Read RF18 while serializing with wifit3's RX/tune/watchdog activity."""
    from wifit3.chips.rtl8821cu_dkms.rf import read_rf

    transport = getattr(driver, "transport", None)
    io_lock = getattr(driver, "_io_lock", None)
    if transport is None or io_lock is None:
        raise TuneError("pinned RTL8821CU driver internals are unavailable")
    loop = asyncio.get_running_loop()
    async with io_lock:
        reader = getattr(driver, "_reader", None)
        if reader is not None:
            paused = await loop.run_in_executor(None, reader.pause, 1.0)
            if not paused:
                reader.resume()
                raise TuneError("RX reader did not confirm pause before RF18 readback")
        try:
            return int(await loop.run_in_executor(None, read_rf, transport, 0x18))
        finally:
            if reader is not None:
                reader.resume()


async def _tune_wifit3_and_read_rf18(driver: RadioDriver, channel: int) -> int:
    """Atomically pause RX, tune, and read RF18 for the pinned driver.

    The upstream ``set_channel`` path requests a pause but ignores its boolean
    acknowledgement.  On this c811, a still-running bulk-IN can race the RF18
    read/modify/write.  This bridge therefore owns one confirmed pause across
    both the channel write and its readback.
    """
    from wifit3.chips.rtl8821cu_dkms import chan
    from wifit3.chips.rtl8821cu_dkms.rf import read_rf

    transport = getattr(driver, "transport", None)
    io_lock = getattr(driver, "_io_lock", None)
    reader = getattr(driver, "_reader", None)
    info = getattr(driver, "info", None)
    if transport is None or io_lock is None or reader is None or info is None:
        raise TuneError("pinned RTL8821CU tune internals are unavailable")
    if not bool(getattr(reader, "running", False)):
        raise TuneError("RX reader is not running before fixed-channel tune")

    loop = asyncio.get_running_loop()
    async with io_lock:
        paused = await loop.run_in_executor(None, reader.pause, 1.0)
        if not paused:
            reader.resume()
            raise TuneError("RX reader did not confirm pause before fixed-channel tune")
        try:
            if bool(getattr(transport, "_mindrove_force_band_bounce", False)):
                # Live c811 validation showed that a repeated 2.4-GHz tune can
                # leave RF18 bit 16 stuck, while a 36→target band transition
                # reliably clears it. Keep both writes inside this one
                # confirmed pause so bulk-IN cannot interleave either RMW.
                transport.current_band = None
                await loop.run_in_executor(
                    None, chan.set_channel, transport, info, RECOVERY_CHANNEL_5GHZ
                )
                # The c811 RF front-end needs a short settling interval after
                # the deliberate band transition.  Immediate back-to-back
                # writes intermittently leave RF18's 5-GHz bit latched even
                # though both register transactions complete successfully.
                await asyncio.sleep(0.03)
                transport._mindrove_force_band_bounce = False
            await loop.run_in_executor(None, chan.set_channel, transport, info, channel)
            await asyncio.sleep(0.05)
            return int(await loop.run_in_executor(None, read_rf, transport, 0x18))
        finally:
            reader.resume()


class Wifit3StationRadio:
    """Station-oriented wrapper over the pinned monitor/injection driver."""

    def __init__(
        self,
        driver: RadioDriver,
        *,
        bssid: bytes,
        station_mac: bytes,
        compatibility_hook: CompatibilityHook = lambda: None,
        rf18_reader: RF18Reader = _read_wifit3_rf18,
        fixed_tuner: Optional[FixedTune] = None,
        retry_hook: TuneRetryHook = _default_retry_hook,
        rx_queue_size: int = 256,
    ) -> None:
        self.driver = driver
        self.bssid = mac_bytes(bssid)
        self.station_mac = mac_bytes(station_mac)
        if self.station_mac[0] & 1:
            raise ValueError("station MAC must be an individual address")
        self._compatibility_hook = compatibility_hook
        self._rf18_reader = rf18_reader
        self._fixed_tuner = fixed_tuner
        self._retry_hook = retry_hook
        self.frames = TargetFrameQueue(
            self.bssid, self.station_mac, maxsize=rx_queue_size, allow_group=True
        )
        self.connected = False
        self.active = False
        self.channel: Optional[int] = None

    @classmethod
    def open_exact(
        cls,
        *,
        bssid: bytes,
        station_mac: bytes,
        rx_queue_size: int = 256,
    ) -> "Wifit3StationRadio":
        """Select exactly one 0bda:c811 using only pinned wifit3 v0.1.5."""
        try:
            import libusb_package
            import usb.core
            import wifit3
            from wifit3.chips.rtl8821cu_dkms import SUPPORTED_IDS, import_driver
        except ImportError as exc:
            raise RadioError(
                "pinned wifit3/PyUSB/libusb dependencies are not installed"
            ) from exc

        detected_version = getattr(wifit3, "__version__", None)
        if detected_version != WIFIT3_VERSION:
            raise RadioError(
                "refusing unreviewed wifit3 version %r; expected %s (%s)"
                % (detected_version, WIFIT3_VERSION, WIFIT3_COMMIT)
            )
        entry = next(
            (
                candidate
                for candidate in SUPPORTED_IDS
                if (candidate.vid, candidate.pid) == (USB_VENDOR_ID, USB_PRODUCT_ID)
            ),
            None,
        )
        if entry is None:
            raise RadioError("pinned wifit3 does not declare exact adapter 0bda:c811")

        backend = libusb_package.get_libusb1_backend()
        devices = list(
            usb.core.find(
                find_all=True,
                idVendor=USB_VENDOR_ID,
                idProduct=USB_PRODUCT_ID,
                backend=backend,
            )
            or ()
        )
        if not devices:
            raise AdapterNotFoundError("MindRove adapter 0bda:c811 was not found")
        if len(devices) != 1:
            raise AdapterNotFoundError(
                "found %d matching 0bda:c811 adapters; attach exactly one" % len(devices)
            )
        driver_type = import_driver()
        driver = driver_type.from_usb_device(devices[0], entry)
        return cls(
            driver,
            bssid=bssid,
            station_mac=station_mac,
            compatibility_hook=install_no_bt_coexist_compatibility,
            rf18_reader=_read_wifit3_rf18,
            fixed_tuner=_tune_wifit3_and_read_rf18,
            retry_hook=_default_retry_hook,
            rx_queue_size=rx_queue_size,
        )

    async def connect(self) -> None:
        if self.connected:
            return
        self._compatibility_hook()
        self.driver.register_rx_callback(self.frames.packet_callback)
        self.driver.register_disconnect_callback(self.frames.disconnect_callback)
        try:
            connected = await self.driver.connect()
            if not connected:
                raise RadioError("pinned driver did not complete cold bring-up")
        except BaseException:
            # A failed cold bring-up can still leave a claimed interface, reader,
            # or firmware session behind. Always give the driver its cleanup path.
            await self.driver.close()
            self.frames.close()
            raise
        self.connected = True

    async def tune_fixed(self, channel: int, *, max_attempts: int = 3) -> int:
        if not self.connected:
            raise RadioError("radio must be connected before tuning")
        if not 1 <= channel <= 11:
            raise ValueError(
                "active MindRove channel must be a US 2.4-GHz channel from 1 through 11"
            )
        if max_attempts <= 0:
            raise ValueError("tune attempts must be positive")
        last_rf18 = 0
        for attempt in range(1, max_attempts + 1):
            if self._fixed_tuner is None:
                await self.driver.set_channel(channel, scan=False)
                last_rf18 = int(await _possibly_await(self._rf18_reader(self.driver)))
            else:
                last_rf18 = int(
                    await _possibly_await(self._fixed_tuner(self.driver, channel))
                )
            if rf18_confirms_2g_channel(last_rf18, channel):
                self.channel = channel
                return last_rf18
            if attempt < max_attempts:
                event = TuneRetry(channel, attempt, max_attempts, last_rf18)
                await _possibly_await(self._retry_hook(self.driver, event))
        raise TuneError(
            "RF18 did not confirm 2.4-GHz channel %d after %d attempts (last 0x%05x)"
            % (channel, max_attempts, last_rf18)
        )

    async def activate_station(self) -> None:
        if not self.connected or self.channel is None:
            raise RadioError("connect and fix the channel before enabling the station MAC")
        active_mac = await self.driver.enter_active_monitor(self.station_mac, self.bssid)
        if bytes(active_mac) != self.station_mac:
            raise RadioError("driver did not activate the requested station MAC")
        self.active = True

    async def send(self, frame: bytes) -> None:
        if not self.active:
            raise RadioError("station MAC is not active")
        if not await self.driver.inject_frame(bytes(frame)):
            raise RadioError("frame injection failed")

    async def receive(self, timeout: Optional[float] = None) -> ReceivedFrame:
        return await self.frames.receive(timeout)

    async def close(self) -> None:
        self.frames.close()
        try:
            if self.active:
                await self.driver.exit_active_monitor()
        finally:
            self.active = False
            if self.connected:
                await self.driver.close()
            self.connected = False
            self.channel = None
