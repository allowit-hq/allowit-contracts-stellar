import { sha256 } from '@noble/hashes/sha256';
const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
// XDR constants: ENVELOPE_TYPE_CONTRACT_ID, CONTRACT_ID_PREIMAGE_FROM_ASSET and the C strkey version byte (2 << 3).
const ENVELOPE_TYPE_CONTRACT_ID = 8, FROM_ASSET = 1, CONTRACT_VERSION = 2 << 3;
const int32 = (value) => [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255];
function crc16(bytes) {
    let crc = 0;
    for (const byte of bytes) {
        crc ^= byte << 8;
        for (let i = 0; i < 8; i++)
            crc = ((crc & 0x8000) ? (crc << 1) ^ 0x1021 : crc << 1) & 0xffff;
    }
    return crc;
}
function base32(bytes) {
    let value = 0, bits = 0, out = '';
    for (const byte of bytes) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out += ALPHABET[(value >>> bits) & 31];
        }
    }
    return out;
}
/**
 * Stellar Asset Contract address for an exact asset code, issuer key and network passphrase. A null issuer means native
 * XLM. Codes are byte-exact, so an issued `XLM` differs from native XLM. Pure: no SDK, wallet or network dependency.
 */
export function stellarAssetContract(code, issuerKey, passphrase) {
    if (!/^[A-Za-z0-9]{1,12}$/.test(code) || (issuerKey === null ? code !== 'XLM' : issuerKey.length !== 32))
        throw new Error('The Stellar asset code or issuer is invalid.');
    const width = code.length <= 4 ? 4 : 12;
    const asset = issuerKey === null ? int32(0) : [
        ...int32(width === 4 ? 1 : 2),
        ...Array.from(code, char => char.charCodeAt(0)), ...new Array(width - code.length).fill(0),
        ...int32(0), ...issuerKey,
    ];
    const preimage = [...int32(ENVELOPE_TYPE_CONTRACT_ID), ...sha256(new TextEncoder().encode(passphrase)), ...int32(FROM_ASSET), ...asset];
    const payload = [CONTRACT_VERSION, ...sha256(Uint8Array.from(preimage))];
    const crc = crc16(payload);
    return base32([...payload, crc & 255, crc >>> 8]);
}
