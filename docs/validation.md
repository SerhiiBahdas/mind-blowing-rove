# Live signal validation

The native macOS bridge has been validated with MindRove Connect on Apple
silicon while the built-in Wi-Fi retained the computer's default internet
route.

## Results

| Stream | Result |
| --- | --- |
| EMG | All eight channels active; 500 Hz acquisition |
| Accelerometer | X/Y/Z active; approximately 50 Hz value updates |
| Gyroscope | X/Y/Z active; approximately 50 Hz value updates |
| Independent short capture | 5,032 finite records with a monotonic counter and no missing samples |
| Extended application log | 500.11 Hz counter-derived rate and 99.909% delivery |

The approximately 50 Hz IMU values are carried inside the 500 Hz acquisition
records. A stationary acceleration magnitude near 1 g and movement-responsive
changes on every accelerometer and gyroscope axis confirmed that the IMU fields
were decoded with the expected units.

The validation session showed substantial mains-frequency common-mode energy
across the EMG channels. This does not indicate a transport failure, but clean
muscle-selective recordings require good electrode, reference, and ground
contact.

## Reproduce the saved-log check

MindRove Connect writes tab-separated data with a `.csv` extension. Validate a
local recording without opening the USB device or binding the application's UDP
port:

```sh
python -m tools.mindrove_bridge.validate_log '<PATH_TO_MINDROVE_LOG>'
```

The validator checks finite values, measurement-counter continuity, acquisition
rate, packet delivery, and activity on all EMG and IMU fields.

## Privacy boundary

This report intentionally contains no raw biosignal samples, recording files,
capture timestamps, usernames, host paths, network names, credentials, device
serials, or captured MAC addresses. Product USB identifiers, protocol ports,
sampling rates, and aggregate validation statistics are non-personal technical
information needed to reproduce the implementation.
