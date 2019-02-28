# u2f-nfchidemu

u2f-nfchidemu is a daemon that provides an emulated HID U2F device by communicating with an actual NFC U2F 
device. For example, it can be used to make the system see an NFC Yubikey as a HID Yubikey, enabling NFC 
use of the key in applications only supporting HID U2F devices, which at the time of writing is all of them 
I know of (pam_u2f, Firefox, Chrome, ..).

## Requirements

* Linux with `CONFIG_UHID` enabled.
* `libnfc`
* An NFC reader supported by `libnfc`.
* Rust (stable) to build.

## Usage

Build the binary with

```
cargo build
```

Afterwards you can run the daemon `sudo target/debug/u2f-nfchidemu`. After opening UHID and NFC handles the 
process changes to user `nobody` and chroots to `/var/empty`.
