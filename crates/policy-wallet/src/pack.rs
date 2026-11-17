//! Packed storage values: positional fields, raw 32-byte keys and LEB128 integers.
//!
//! The wallet writes every stored value itself from checked owner input, so a value that does not
//! decode is `InvalidState`, and an owner value that does not fit is `InvalidParam`.
use crate::AllowitWalletError as Error;
use allowit::{AllowitValue, MAX_ITEMS, MAX_TEXT};
use soroban_sdk::{Address, BytesN, Env, String, Vec, address_payload::AddressPayload, xdr::ToXdr};

/// Appends to a fixed buffer.
pub(crate) struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Writer<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }
    /// The bytes written so far.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
    pub(crate) fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self
            .len
            .checked_add(bytes.len())
            .filter(|end| *end <= self.buf.len())
            .ok_or(Error::InvalidParam)?;
        self.buf[self.len..end].copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
    pub(crate) fn byte(&mut self, byte: u8) -> Result<(), Error> {
        self.put(&[byte])
    }
    /// Unsigned LEB128.
    pub(crate) fn uint(&mut self, mut value: u128) -> Result<(), Error> {
        loop {
            let low = (value & 0x7f) as u8;
            value >>= 7;
            if value == 0 {
                return self.byte(low);
            }
            self.byte(low | 0x80)?;
        }
    }
    /// A nonnegative integer as unsigned LEB128; a negative one is `InvalidState`.
    pub(crate) fn amount(&mut self, value: i128) -> Result<(), Error> {
        self.uint(u128::try_from(value).map_err(|_| Error::InvalidState)?)
    }
    /// Zigzag LEB128.
    pub(crate) fn int(&mut self, value: i128) -> Result<(), Error> {
        self.uint(((value << 1) ^ (value >> 127)) as u128)
    }
}

/// Reads a buffer from the front.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    pub(crate) fn done(&self) -> bool {
        self.pos == self.buf.len()
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.buf.len())
            .ok_or(Error::InvalidState)?;
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    pub(crate) fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn key(&mut self) -> Result<[u8; 32], Error> {
        let mut key = [0; 32];
        key.copy_from_slice(self.take(32)?);
        Ok(key)
    }
    pub(crate) fn uint(&mut self) -> Result<u128, Error> {
        let mut value = 0u128;
        let mut shift = 0u32;
        loop {
            let byte = self.byte()?;
            let low = u128::from(byte & 0x7f);
            if shift > 126 || (shift == 126 && low > 3) {
                return Err(Error::InvalidState);
            }
            value |= low << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }
    /// A nonnegative amount within `i128`.
    pub(crate) fn amount(&mut self) -> Result<i128, Error> {
        i128::try_from(self.uint()?).map_err(|_| Error::InvalidState)
    }
    pub(crate) fn int(&mut self) -> Result<i128, Error> {
        let value = self.uint()?;
        Ok(((value >> 1) as i128) ^ -((value & 1) as i128))
    }
}

const INT: u8 = 0;
const FALSE: u8 = 1;
const TRUE: u8 = 2;
const TEXT: u8 = 3;
const ACCOUNT: u8 = 4;
const CONTRACT: u8 = 5;
const LIST: u8 = 6;

/// An account (`G…`) or contract (`C…`) address as a kind byte and its raw 32 bytes. Any other
/// address kind is `InvalidParam`.
pub(crate) fn put_address(w: &mut Writer, address: &Address) -> Result<(), Error> {
    match address.to_payload() {
        Some(AddressPayload::AccountIdPublicKeyEd25519(key)) => {
            w.byte(ACCOUNT)?;
            w.put(&key.to_array())
        }
        Some(AddressPayload::ContractIdHash(hash)) => {
            w.byte(CONTRACT)?;
            w.put(&hash.to_array())
        }
        None => Err(Error::InvalidParam),
    }
}

/// The address of a kind byte and raw key.
pub(crate) fn address(env: &Env, kind: u8, key: &[u8; 32]) -> Result<Address, Error> {
    let key = BytesN::from_array(env, key);
    let payload = match kind {
        ACCOUNT => AddressPayload::AccountIdPublicKeyEd25519(key),
        CONTRACT => AddressPayload::ContractIdHash(key),
        _ => return Err(Error::InvalidState),
    };
    Ok(Address::from_payload(env, payload))
}

/// One param value. Core's `check_value` has already bounded it.
pub(crate) fn put_value(w: &mut Writer, value: &AllowitValue) -> Result<(), Error> {
    match value {
        AllowitValue::Int(n) => {
            w.byte(INT)?;
            w.int(*n)
        }
        AllowitValue::Bool(flag) => w.byte(if *flag { TRUE } else { FALSE }),
        AllowitValue::Str(text) => {
            let len = text.len() as usize;
            if len > MAX_TEXT as usize {
                return Err(Error::InvalidParam);
            }
            let mut bytes = [0u8; MAX_TEXT as usize];
            text.copy_into_slice(&mut bytes[..len]);
            w.byte(TEXT)?;
            w.uint(len as u128)?;
            w.put(&bytes[..len])
        }
        AllowitValue::Addr(address) => put_address(w, address),
        AllowitValue::List(items) => {
            w.byte(LIST)?;
            w.uint(u128::from(items.len()))?;
            for item in items.try_iter() {
                put_value(w, &item.map_err(|_| Error::InvalidParam)?)?;
            }
            Ok(())
        }
    }
}

pub(crate) fn get_value(env: &Env, r: &mut Reader) -> Result<AllowitValue, Error> {
    Ok(match r.byte()? {
        INT => AllowitValue::Int(r.int()?),
        FALSE => AllowitValue::Bool(false),
        TRUE => AllowitValue::Bool(true),
        TEXT => {
            let len = r.uint()?;
            if len > u128::from(MAX_TEXT) {
                return Err(Error::InvalidState);
            }
            AllowitValue::Str(String::from_bytes(env, r.take(len as usize)?))
        }
        kind @ (ACCOUNT | CONTRACT) => AllowitValue::Addr(address(env, kind, &r.key()?)?),
        LIST => {
            let count = r.uint()?;
            if count > u128::from(MAX_ITEMS) {
                return Err(Error::InvalidState);
            }
            let mut items = Vec::new(env);
            for _ in 0..count {
                items.push_back(get_value(env, r)?);
            }
            AllowitValue::List(items)
        }
        _ => return Err(Error::InvalidState),
    })
}

/// The characters of a symbol, from its canonical XDR: type, length, then the padded bytes. A
/// symbol holds at most 32 characters.
pub(crate) fn symbol_text(
    env: &Env,
    symbol: &soroban_sdk::Symbol,
    out: &mut [u8; 32],
) -> Result<usize, Error> {
    let xdr = symbol.clone().to_xdr(env);
    let len = xdr.len() as usize;
    if !(8..=40).contains(&len) {
        return Err(Error::InvalidParam);
    }
    let mut raw = [0u8; 40];
    xdr.copy_into_slice(&mut raw[..len]);
    let n = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    if n == 0 || n > 32 || 8 + n > len {
        return Err(Error::InvalidParam);
    }
    out[..n].copy_from_slice(&raw[8..8 + n]);
    Ok(n)
}
