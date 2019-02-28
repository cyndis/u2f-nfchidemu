use std::io::{Read, Write};

#[allow(warnings)]
mod uhid;
mod nfc;

static FIDO_DESCRIPTOR: &'static [u8] = &[
    0x06, 0xd0, 0xf1,        /* USAGE (2B)   FIDO */
    0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81,
    0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xc0
];

struct Uhid {
    f: std::fs::File,
}

impl Uhid {
    pub fn new() -> Result<Uhid, Box<std::error::Error>> {
        Ok(Uhid {
            f: std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/uhid")?
        })
    }

    pub fn write(&mut self, event: &uhid::uhid_event) -> Result<(), Box<std::error::Error>> {
        let slice = unsafe {
            std::slice::from_raw_parts(event as *const uhid::uhid_event as *const u8,
                                       std::mem::size_of::<uhid::uhid_event>())
        };

        self.f.write(&slice)?;

        Ok(())
    }

    pub fn read(&mut self) -> Result<uhid::uhid_event, Box<std::error::Error>> {
        let mut event: uhid::uhid_event = unsafe { std::mem::zeroed() };
        let slice = unsafe {
            std::slice::from_raw_parts_mut(&mut event as *mut uhid::uhid_event as *mut u8,
                                           std::mem::size_of::<uhid::uhid_event>())
        };

        self.f.read(slice)?;

        Ok(event)
    }
}

fn copy_bytes(from: &[u8], to: &mut [u8]) {
    assert!(to.len() >= from.len());

    to[0..from.len()].copy_from_slice(from);
}

#[derive(Debug)]
struct PendingData {
    cid: u32,
    cmd: u8,
    len: usize,
    data: Vec<u8>,
}

#[derive(Debug)]
struct HidMessage {
    cid: u32,
    cmd: u8,
    data: Vec<u8>,
}

struct Hid<'a> {
    uhid: &'a mut Uhid,
    pending: Option<PendingData>,
}

impl<'a> Drop for Hid<'a> {
    fn drop(&mut self) {
        let mut req: uhid::uhid_event = unsafe { std::mem::zeroed() };
        req.type_ = uhid::uhid_event_type_UHID_DESTROY;

        let _ = self.uhid.write(&req);
    }
}

impl<'a> Hid<'a> {
    fn new(uhid: &'a mut Uhid) -> Result<Hid<'a>, Box<std::error::Error>> {
        let mut req: uhid::uhid_event = unsafe { std::mem::zeroed() };
        req.type_ = uhid::uhid_event_type_UHID_CREATE2;
        unsafe {
            copy_bytes(b"U2F-NFC HID Emulation Device", &mut req.u.create2.name);
            copy_bytes(FIDO_DESCRIPTOR, &mut req.u.create2.rd_data);
            req.u.create2.rd_size = FIDO_DESCRIPTOR.len() as u16;
            req.u.create2.bus = 0x5;
            req.u.create2.vendor = 0xfffe;
            req.u.create2.product = 0x0000;
        }

        uhid.write(&req)?;

        Ok(Hid { uhid, pending: None })
    }

    fn read(&mut self) -> Result<HidMessage, Box<std::error::Error>> {
        loop {
            let event = self.uhid.read()?;

            match event.type_ {
                uhid::uhid_event_type_UHID_OUTPUT => {
                    let e = unsafe { &event.u.output };
                    let data = &e.data[1..e.size as usize];

                    if let Some(msg) = self.process_frame(data) {
                        return Ok(msg);
                    }
                }
                _ => (),
            }
        }
    }

    fn process_frame(&mut self, data: &[u8]) -> Option<HidMessage> {
        let mut cid = 0;
        cid |= (data[0] as u32) << 24;
        cid |= (data[1] as u32) << 16;
        cid |= (data[2] as u32) << 8;
        cid |= (data[3] as u32) << 0;

        let cmd = data[4] & !(1<<7);
        let init = data[4] & (1<<7) != 0;

        if init && self.pending.is_some() {
            eprintln!("ERROR: Got new while another one in progress");
            self.pending = None;
        }

        if init {
            let len = ((data[5] as usize) << 8) | (data[6] as usize);
            let mut pending = PendingData { cid, cmd, len, data: vec![] };

            let initial_len = len.min(64-7);
            let payload = &data[7..7+initial_len];

            pending.data.extend_from_slice(payload);
            self.pending = Some(pending);
        } else {
            if let Some(pending) = self.pending.as_mut() {
                let remaining = pending.len - pending.data.len();
                let remaining_this = remaining.min(64-5);
                let payload = &data[5..5+remaining_this];
                pending.data.extend_from_slice(payload);
            }
        }

        if self.pending.as_ref().map(|x| x.data.len() == x.len).unwrap_or(false) {
            let d = self.pending.take().unwrap();
            Some(HidMessage { cid: d.cid, cmd: d.cmd, data: d.data })
        } else {
            None
        }
    }

    fn write(&mut self, msg: &HidMessage) -> Result<(), Box<std::error::Error>> {
        let mut remaining = &msg.data[0..];

        let mut segment = 0;
        while !remaining.is_empty() {
            let mut reply = vec![];
            reply.push(((msg.cid >> 24) & 0xff) as u8);
            reply.push(((msg.cid >> 16) & 0xff) as u8);
            reply.push(((msg.cid >> 8) & 0xff) as u8);
            reply.push(((msg.cid >> 0) & 0xff) as u8);

            let space;
            if segment == 0 {
                reply.push(msg.cmd | (1<<7));
                reply.push(((msg.data.len() >> 8) & 0xff) as u8);
                reply.push(((msg.data.len() >> 0) & 0xff) as u8);
                space = 64-7;
            } else {
                reply.push(segment-1);
                space = 64-5;
            }

            let this_len = remaining.len().min(space);
            reply.extend_from_slice(&remaining[0..this_len]);
            remaining = &remaining[this_len..];

            let mut req: uhid::uhid_event = unsafe { std::mem::zeroed() };
            req.type_ = uhid::uhid_event_type_UHID_INPUT2;
            unsafe {
                req.u.input2.size = 64;//reply.len() as u16;
                copy_bytes(&reply, &mut req.u.input2.data);
            }

            self.uhid.write(&req)?;

            segment += 1;
        }

        Ok(())
    }
}

static APDU_SELECT: &'static [u8] = &[
    0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01
];

fn parse_response(data: &[u8]) -> Result<&[u8], u16> {
    let status = ((data[data.len()-2] as u16) << 8) | (data[data.len()-1] as u16);
    if status == 0x9000 {
        Ok(&data[0..data.len()-2])
    } else {
        Err(status)
    }
}

static DEVICE_CHIP_ERROR_MESSAGE: &'static str =
    "Device chip error, retrying. Note that registration does not work over NFC on Yubikey tokens.";

fn main() -> Result<(), Box<std::error::Error>> {
    let mut nfc_context = nfc::Context::new()?;
    let mut nfc_device = nfc_context.open_initiator()?;
    let mut uhid = Uhid::new()?;

    privdrop::PrivDrop::default()
        .chroot("/var/empty")
        .user("nobody")?
        .apply()?;

    loop {
        /* Find NFC device. */
        while nfc_device.poll_target()?.is_none() {
        }

        let mut response = [0u8; 16];
        let len = match nfc_device.transceive(APDU_SELECT, &mut response) {
            Ok(len) => len,
            Err(nfc::Error::TimedOut) => {
                continue;
            }
            err => err?,
        };

        parse_response(&response[0..len])
            .map_err(|_| "Error status received from APDU SELECT")?;

        eprintln!("Found NFC device.");

        /* Got NFC device. */

        let mut hid = Hid::new(&mut uhid)?;

        loop {
            let msg = hid.read()?;

            match (msg.cid, msg.cmd) {
                (0xffff_ffff, 0x6) => {
                    // HID_INIT
                    let nonce = &msg.data[0..8];

                    let mut reply = vec![];
                    reply.extend_from_slice(nonce);
                    reply.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd,
                                              0x1,
                                              0x1, 0x0, 0x0,
                                              0x0,
                                            ]);

                    hid.write(&HidMessage { cid: 0xffff_ffff, cmd: 0x6, data: reply })?;
                }
                (_, 0x3) => {
                    // HID_MSG
                    let mut response = [0u8; 65536];
                    let len = match nfc_device.transceive(&msg.data, &mut response) {
                        Ok(len) => len,
                        Err(nfc::Error::RfTransmissionError) => {
                            // Lost device, retry
                            eprintln!("NFC device lost.");
                            break;
                        }
                        Err(nfc::Error::DeviceChipError) => {
                            eprintln!("{}", DEVICE_CHIP_ERROR_MESSAGE);
                            continue;
                        }
                        err => err?,
                    };

                    let buf = &response[0..len];

                    let msg = HidMessage { cid: msg.cid, cmd: 0x3, data: buf.to_owned() };
                    hid.write(&msg)?;
                }
                _ => {
                    eprintln!("Unknown cid/cmd 0x{:08x}/0x{:02x}", msg.cid, msg.cmd);

                    let reply = vec![0x01];
                    let msg = HidMessage { cid: msg.cid, cmd: 0x3f, data: reply };
                    hid.write(&msg)?;
                }
            }
        }
    }
}
