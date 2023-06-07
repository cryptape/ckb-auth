extern crate alloc;

use alloc::ffi::CString;
use alloc::ffi::NulError;
use alloc::format;
use ckb_std::{
    ckb_types::core::ScriptHashType,
    dynamic_loading_c_impl::{CKBDLContext, Library, Symbol},
    high_level::exec_cell,
    syscalls::SysError,
};
use log::info;
// use core::ffi::CStr;
use alloc::collections::BTreeMap;
use core::mem::size_of_val;
use core::mem::transmute;
use hex::encode;

#[derive(Debug)]
pub enum CkbAuthError {
    UnknowAlgorithmID,
    DynamicLinkingUninit,
    LoadDLError,
    LoadDLFuncError,
    RunDLError,
    ExecError(SysError),
    EncodeArgs,
}

impl From<SysError> for CkbAuthError {
    fn from(err: SysError) -> Self {
        info!("exec error: {:?}", err);
        Self::ExecError(err)
    }
}

impl From<NulError> for CkbAuthError {
    fn from(err: NulError) -> Self {
        info!("Exec encode args failed: {:?}", err);
        Self::EncodeArgs
    }
}

#[derive(Clone)]
pub enum AuthAlgorithmIdType {
    Ckb = 0,
    Ethereum = 1,
    Eos = 2,
    Tron = 3,
    Bitcoin = 4,
    Dogecoin = 5,
    CkbMultisig = 6,
    Schnorr = 7,
    Rsa = 8,
    Iso97962 = 9,
    OwnerLock = 0xFC,
}

impl Into<u8> for AuthAlgorithmIdType {
    fn into(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for AuthAlgorithmIdType {
    type Error = CkbAuthError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if (value >= AuthAlgorithmIdType::Ckb.into()
            && value <= AuthAlgorithmIdType::Iso97962.into())
            || value == AuthAlgorithmIdType::OwnerLock.into()
        {
            Ok(unsafe { transmute(value) })
        } else {
            Err(CkbAuthError::UnknowAlgorithmID)
        }
    }
}

pub struct CkbAuthType {
    pub algorithm_id: AuthAlgorithmIdType,
    pub pubkey_hash: [u8; 20],
}

pub enum EntryCategoryType {
    Exec = 0,
    DynamicLinking = 1,
    // Spawn = 2,
}

impl TryFrom<u8> for EntryCategoryType {
    type Error = CkbAuthError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Exec),
            1 => Ok(Self::DynamicLinking),
            _ => Err(CkbAuthError::EncodeArgs),
        }
    }
}

pub struct CkbEntryType {
    pub code_hash: [u8; 32],
    pub hash_type: ScriptHashType,
    pub entry_category: EntryCategoryType,
}

pub fn ckb_auth(
    entry: &CkbEntryType,
    id: &CkbAuthType,
    signature: &[u8],
    message: &[u8; 32],
) -> Result<(), CkbAuthError> {
    match entry.entry_category {
        EntryCategoryType::Exec => ckb_auth_exec(entry, id, signature, message),
        EntryCategoryType::DynamicLinking => ckb_auth_dl(entry, id, signature, message),
    }
}

fn ckb_auth_exec(
    entry: &CkbEntryType,
    id: &CkbAuthType,
    signature: &[u8],
    message: &[u8; 32],
) -> Result<(), CkbAuthError> {
    let args = CString::new(format!(
        "{}:{:02X?}:{:02X?}:{}:{}:{}",
        encode(&entry.code_hash),
        entry.hash_type as u8,
        id.algorithm_id.clone() as u8,
        encode(signature),
        encode(message),
        encode(id.pubkey_hash)
    ))?;

    // args     id + pubhash + code_hash + hash_type + entry_category
    // witness  sign

    // info!("args: {:?}", args);
    exec_cell(&entry.code_hash, entry.hash_type, 0, 0, &[args.as_c_str()])?;
    Ok(())
}

type DLContext = CKBDLContext<[u8; 512 * 1024]>;
type CkbAuthValidate = unsafe extern "C" fn(
    auth_algorithm_id: u8,
    signature: *const u8,
    signature_size: u32,
    message: *const u8,
    message_size: u32,
    pubkey_hash: *mut u8,
    pubkey_hash_size: u32,
) -> i32;

const EXPORTED_FUNC_NAME: &str = "ckb_auth_validate";

struct CKBDLLoader {
    pub context: DLContext,
    pub context_used: usize,
    pub loaded_lib: BTreeMap<[u8; 33], Library>,
}

static mut G_CKB_DL_LOADER: Option<CKBDLLoader> = None;
impl CKBDLLoader {
    pub fn get() -> &'static mut Self {
        unsafe {
            match G_CKB_DL_LOADER.as_mut() {
                Some(v) => v,
                None => {
                    G_CKB_DL_LOADER = Some(Self::new());
                    G_CKB_DL_LOADER.as_mut().unwrap()
                }
            }
        }
    }

    fn new() -> Self {
        Self {
            context: unsafe { DLContext::new() },
            context_used: 0,
            loaded_lib: BTreeMap::new(),
        }
    }

    fn get_lib(
        &mut self,
        code_hash: &[u8; 32],
        hash_type: ScriptHashType,
    ) -> Result<&Library, CkbAuthError> {
        let mut lib_key = [0u8; 33];
        lib_key[..32].copy_from_slice(code_hash);
        lib_key[32] = hash_type as u8;

        let has_lib = match self.loaded_lib.get(&lib_key) {
            Some(_) => true,
            None => false,
        };

        if !has_lib {
            info!("loading library");
            let size = size_of_val(&self.context);
            let lib = self
                .context
                .load_with_offset(code_hash, hash_type, self.context_used, size)
                .map_err(|_| CkbAuthError::LoadDLError)?;
            self.context_used += lib.consumed_size();
            self.loaded_lib.insert(lib_key.clone(), lib);
        };
        Ok(self.loaded_lib.get(&lib_key).unwrap())
    }

    pub fn get_validate_func<T>(
        &mut self,
        code_hash: &[u8; 32],
        hash_type: ScriptHashType,
        func_name: &str,
    ) -> Result<Symbol<T>, CkbAuthError> {
        let lib = self.get_lib(code_hash, hash_type)?;

        let func: Option<Symbol<T>> = unsafe { lib.get(func_name.as_bytes()) };
        if func.is_none() {
            return Err(CkbAuthError::LoadDLFuncError);
        }
        Ok(func.unwrap())
    }
}

fn ckb_auth_dl(
    entry: &CkbEntryType,
    id: &CkbAuthType,
    signature: &[u8],
    message: &[u8; 32],
) -> Result<(), CkbAuthError> {
    let func: Symbol<CkbAuthValidate> = CKBDLLoader::get().get_validate_func(
        &entry.code_hash,
        entry.hash_type,
        EXPORTED_FUNC_NAME,
    )?;

    let mut pub_key = id.pubkey_hash.clone();
    let rc_code = unsafe {
        func(
            id.algorithm_id.clone().into(),
            signature.as_ptr(),
            signature.len() as u32,
            message.as_ptr(),
            message.len() as u32,
            pub_key.as_mut_ptr(),
            pub_key.len() as u32,
        )
    };

    match rc_code {
        0 => Ok(()),
        _ => {
            info!("run auth error({}) in dynamic linking", rc_code);
            Err(CkbAuthError::RunDLError)
        }
    }
}
