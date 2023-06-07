use ckb_std::error::SysError;


// TODO
#[derive(Debug)]
#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,

    WrongHex = 20,
    ChainedExec,
    InvalidCellDepRef,
    InvalidDataLength,
    InvalidCellDepTypeScript,
    InvalidInputCount,
    InvalidOutputLockScript,
    InvalidUpdate,
    WrongGlobalRegistry,
    OutputTypeForbidden,
    InvalidLinkedList,
    Changed,

    // transforming
    OverlapPair,
    DanglingPair,

    Unknown,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}
