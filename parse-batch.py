import rlp
import sys
import json
from Crypto.Hash import keccak

if len(sys.argv) != 3:
    print('Usage: python parse-batch.py <input_hex_file> <output_json_file>')

CHAIN_ID = 1101

def change_v(v: bytes) -> int:
    return int.from_bytes(v, 'big') - 27 + CHAIN_ID * 2 + 35

if __name__ == '__main__':
    inputfile, outputfile = sys.argv[1], sys.argv[2]
    with open(inputfile, 'r') as f:
        batch = f.read()

    if batch[:2] == '0x':
        batch = bytes.fromhex(batch[2:])
    else:
        batch = bytes.fromhex(batch)

    assert batch[0] == 0x0b, 'First transaction must be a change L2 block transaction if it is NOT a forced batch'
    txs = []

    # ;;;;;;;;;;;;;;;;;;
    # ;; A - Initialization
    # ;;     - Data to parse
    # ;;         - legacy transaction: [rlp(nonce, gasprice, gaslimit, to, value, data, chainId, 0, 0)|r|s|v|effectivePercentage]
    # ;;         - pre EIP-155 transaction (https://eips.ethereum.org/EIPS/eip-155): [rlp(nonce, gasprice, gaslimit, to, value, data)|r|s|v|effectivePercentage]
    # ;;         - internal transaction changeL2Block: [txType, deltaTimestamp, indexL1InfoTree]
    # ;;      - Signed Ethereum transaction
    # ;;         - legacy transaction: H_keccak(rlp(nonce, gasprice, gaslimit, to, value, data, chainId, 0, 0))
    # ;;         - pre EIP-155 transaction: H_keccak(rlp(nonce, gasprice, gaslimit, to, value, data))
    # ;;     - RLP encoding information: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp
    # ;;     - Entire batch is discarded (no transaction is processed) if any error is found
    # ;;;;;;;;;;;;;;;;;;

    # ;;;;;;;;;;;;;;;;;;
    # ;; ChangeL2BlockTx:
    # ;;   - fields: [type | deltaTimestamp | indexL1InfoTree ]
    # ;;   - bytes:  [  1  |       4        |        4        ]
    # ;;;;;;;;;;;;;;;;;;

    idx = 0
    while idx < len(batch):
        if batch[idx] == 0x0b: # ChangeL2Block Tx
            typ = batch[idx]
            idx += 1
            deltaTimestamp = int.from_bytes(batch[idx:idx+4], 'big')
            idx += 4
            indexL1InfoTree = int.from_bytes(batch[idx:idx+4], 'big')
            idx += 4
            tx = {
                'type': typ,
                'deltaTimestamp': deltaTimestamp,
                'indexL1InfoTree': indexL1InfoTree
            }
        else: # Normal transaction
            off = batch[idx]
            assert off >= 0xc0, "Invalid offset"
            lenOfListLen = 0
            if off <= 0xf7:
                txlen = off - 0xc0
            else:
                lenOfListLen = off - 0xf7
                txlen = int.from_bytes(batch[idx+1:idx+1+lenOfListLen], 'big')
            total_length = txlen + lenOfListLen + 1
            tx = rlp.decode(batch[idx:idx + total_length])
            idx += total_length
            r, s, v, effectivePercentage = batch[idx:idx+32], batch[idx+32:idx+64], batch[idx+64:idx+65], batch[idx+65]
            signed_tx_raw = rlp.encode(tx[:6] + [change_v(v), r, s])
            signed_tx_hash = keccak.new(digest_bits=256).update(signed_tx_raw).digest()
            idx += 66
            d = {}
            # rlp(nonce, gasprice, gaslimit, to, value, data, chainId, 0, 0)
            d['nonce'] = int.from_bytes(tx[0], 'big')
            d['gasprice'] = int.from_bytes(tx[1], 'big')
            d['gaslimit'] = int.from_bytes(tx[2], 'big')
            d['to'] = '0x' + tx[3].hex()
            d['value'] = int.from_bytes(tx[4], 'big')
            d['data'] = '0x' + tx[5].hex()
            if len(tx) == 9:
                d['chainId'] = int.from_bytes(tx[6], 'big')
            tx = {
                'hash': '0x' + signed_tx_hash.hex(),
                'raw': '0x' + signed_tx_raw.hex(),
                'payload': d,
                'signature': {
                    'r': '0x' + r.hex(),
                    's': '0x' + s.hex(),
                    'v': '0x' + v.hex() 
                },
                'effectivePercentage': effectivePercentage
            }
        txs.append(tx)

    with open(outputfile, 'w') as f:
        f.write(json.dumps(txs, indent=4))
