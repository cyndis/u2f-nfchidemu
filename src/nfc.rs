use std::os::raw::c_int;
use std::rc::Rc;

#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum Error {
    ContextInitializationFailed,
    DeviceInitializationFailed,
    IoError,
    InvalidArgument,
    NotSupported,
    NoSuchDevice,
    BufferOverflow,
    TimedOut,
    Aborted,
    NotImplemented,
    TargetReleased,
    RfTransmissionError,
    MifareAuthenticationFailed,
    SoftwareError,
    DeviceChipError,
}

impl From<c_int> for Error {
    fn from(err: c_int) -> Error {
        use self::Error::*;

        match err {
            -1  => IoError,
            -2  => InvalidArgument,
            -3  => NotSupported,
            -4  => NoSuchDevice,
            -5  => BufferOverflow,
            -6  => TimedOut,
            -7  => Aborted,
            -8  => NotImplemented,
            -10 => TargetReleased,
            -20 => RfTransmissionError,
            -30 => MifareAuthenticationFailed,
            -80 => SoftwareError,
            -90 => DeviceChipError,
            _   => panic!("Invalid error"),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        use self::Error::*;

        let message = match *self {
            ContextInitializationFailed => "Failed to initialize libnfc context",
            DeviceInitializationFailed => "Failed to open NFC reader device",
            IoError => "I/O error",
            InvalidArgument => "Invalid argument",
            NotSupported => "Operation not supported by NFC reader device",
            NoSuchDevice => "No such device",
            BufferOverflow => "Buffer overflow",
            TimedOut => "Operation timed out",
            Aborted => "Operation aborted by user",
            NotImplemented => "Not implemented",
            TargetReleased => "Target was released",
            RfTransmissionError => "RF transmission error",
            MifareAuthenticationFailed => "MIFARE Classic authentication failed",
            SoftwareError => "Software error",
            DeviceChipError => "NFC reader device error",
        };

        write!(f, "{}", message)
    }
}

impl std::error::Error for Error {
}

pub struct ContextInner(*mut nfc_sys::nfc_context);
pub struct Context(Rc<ContextInner>);

impl Context {
    fn get(&self) -> *mut nfc_sys::nfc_context {
        (self.0).0
    }

    pub fn new() -> Result<Context, Error> {
        let mut ptr = std::ptr::null_mut();

        unsafe {
            nfc_sys::nfc_init(&mut ptr);
        }

        if ptr.is_null() {
            Err(Error::ContextInitializationFailed)
        } else {
            Ok(Context(Rc::new(ContextInner(ptr))))
        }
    }

    pub fn open_initiator(&mut self) -> Result<Initiator, Error> {
        let ptr = unsafe {
            nfc_sys::nfc_open(self.get(), std::ptr::null())
        };

        if ptr.is_null() {
            return Err(Error::DeviceInitializationFailed);
        }

        let err = unsafe {
            nfc_sys::nfc_initiator_init(ptr)
        };

        if err < 0 {
            Err(err.into())
        } else {
            Ok(Initiator(ptr, self.0.clone()))
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            nfc_sys::nfc_exit(self.get());
        }
    }
}

pub struct Initiator(*mut nfc_sys::nfc_device, Rc<ContextInner>);

impl Initiator {
    fn get(&self) -> *mut nfc_sys::nfc_device {
        self.0
    }

    pub fn poll_target(&mut self) -> Result<Option<Target>, Error> {
        let modulation = nfc_sys::nfc_modulation {
            nmt: nfc_sys::nfc_modulation_type::NMT_ISO14443A,
            nbr: nfc_sys::nfc_baud_rate::NBR_106,
        };

        let mut target = nfc_sys::nfc_target::default();

        let err = unsafe {
            nfc_sys::nfc_initiator_poll_target(self.get(), &modulation, 1, 1, 1, &mut target)
        };

        if err < 0 {
            Err(err.into())
        } else if err == 0 {
            Ok(None)
        } else {
            Ok(Some(Target(target)))
        }
    }

    pub fn transceive(&mut self, transmit: &[u8], receive: &mut [u8]) -> Result<usize, Error> {
        let err = unsafe {
            nfc_sys::nfc_initiator_transceive_bytes(self.get(), transmit.as_ptr(), transmit.len(),
                                                    receive.as_mut_ptr(), receive.len(), 0)
        };

        if err < 0 {
            Err(err.into())
        } else {
            Ok(err as usize)
        }
    }
}

pub struct Target(nfc_sys::nfc_target);
