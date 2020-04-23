import argparse

from classes import *
from opcodes import *


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("bytecode", type=Bytes.fromhex, help="Contract bytecode")
    parser.add_argument(
        "-e",
        "--entrypoint",
        type=Bytes.fromhex,
        default=Bytes([0xFF] * 20),
        help="Entry point address. Defaults to 0xffffffffffffffffffffffffffffffffffffffff",
    )
    args = parser.parse_args()
    process(args.bytecode, args.entrypoint)


def split_metadata(code_bytes: Bytes) -> (Bytes, Bytes):
    metadata_bytes = Bytes()
    metadata_length = code_bytes[-2:].int() + 2
    if (
        metadata_length < len(code_bytes)
        and 0xA0 <= code_bytes[-metadata_length] <= 0xB7
        and 0x60 <= code_bytes[-metadata_length + 1] <= 0x7B
    ):
        metadata_bytes = code_bytes[-metadata_length:]
        code_bytes = code_bytes[:-metadata_length]
    return code_bytes, metadata_bytes


def split_and_analyze_constructor(code_bytes: Bytes) -> (Bytes, Bytecode, int):
    constructor_bytecode = Bytecode.frombytes(code_bytes, stop_opcodes={Op.CODECOPY})
    assert constructor_bytecode[-1].opcode == Op.CODECOPY
    PUSH_idxs = [
        idx
        for idx in range(len(constructor_bytecode))
        if constructor_bytecode[idx].opcode in PUSH_OPCODES
    ]
    assert constructor_bytecode[PUSH_idxs[-1]].data.int() == 0
    assert all(
        constructor_bytecode[idx].opcode in (Op.PUSH1, Op.PUSH2)
        for idx in PUSH_idxs[-3:-1]
    )
    length_idx, offset_idx = PUSH_idxs[-3:-1]
    offset, length = (
        constructor_bytecode[offset_idx].data.int(),
        constructor_bytecode[length_idx].data.int(),
    )
    assert offset + length == len(code_bytes)
    constructor_bytecode += Bytecode.frombytes(
        code_bytes[constructor_bytecode.byte_length() : offset],
        stop_opcodes={Op.JUMPDEST},
    )
    assert constructor_bytecode[-1].opcode != Op.JUMPDEST
    if constructor_bytecode[length_idx].opcode == Op.PUSH1:
        constructor_bytecode[length_idx] = Op.PUSH2(Bytes.zero(2))
        if constructor_bytecode[offset_idx].opcode == Op.PUSH1:
            constructor_bytecode[offset_idx] = Op.PUSH2(Bytes.fromint(offset + 2))
        else:
            constructor_bytecode[offset_idx].set_data(Bytes.fromint(offset + 1))
    code_bytes = code_bytes[offset:]
    return code_bytes, constructor_bytecode, length_idx


def process(code_bytes: Bytes, entrypoint: Bytes):
    (
        main_code_bytes,
        constructor_bytecode,
        constructor_length_idx,
    ) = split_and_analyze_constructor(code_bytes)
    contract_code_bytes, metadata_bytes = split_metadata(main_code_bytes)

    contract_bytecode = create_aa_bytecode(entrypoint)
    jumpdests = []
    routing_push_idxs = []
    ptr = 0
    offset = contract_bytecode.byte_length()

    while True:
        next_bytecode = Bytecode.frombytes(
            contract_code_bytes[ptr:], stop_opcodes={Op.JUMP, Op.JUMPI, Op.JUMPDEST}
        )
        length = next_bytecode.byte_length()
        ptr += length - 1

        if next_bytecode[-1].opcode == Op.JUMPDEST:
            jumpdests.append((ptr, offset + ptr))
            contract_bytecode += next_bytecode

        elif next_bytecode[-1].opcode == Op.JUMP:
            contract_bytecode += next_bytecode[:-1]

            extra_bytecode = Bytecode([Op.PUSH2(Bytes.zero(2)), Op.JUMP()])
            contract_bytecode += extra_bytecode
            offset += extra_bytecode.byte_length() - 1

            routing_push_idxs.append(len(contract_bytecode) - 2)

        elif next_bytecode[-1].opcode == Op.JUMPI:
            contract_bytecode += next_bytecode[:-1]

            extra_bytecode = Bytecode(
                [Op.SWAP1(), Op.PUSH2(Bytes.zero(2)), Op.JUMPI(), Op.POP()]
            )
            contract_bytecode += extra_bytecode
            offset += extra_bytecode.byte_length() - 1

            routing_push_idxs.append(len(contract_bytecode) - 3)

        else:
            contract_bytecode += next_bytecode
            break

        ptr += 1

    routing_exit_ptr = offset + len(contract_code_bytes)
    routing_exit_bytecode = Bytecode([Op.JUMPDEST(), Op.SWAP1(), Op.POP(), Op.JUMP()])
    contract_bytecode += routing_exit_bytecode
    offset += routing_exit_bytecode.byte_length()

    routing_ptr = offset + len(contract_code_bytes)
    routing_bytecode = Bytecode([Op.JUMPDEST()])
    for old_ptr, new_ptr in jumpdests:
        routing_bytecode += Bytecode(
            [
                Op.PUSH2(Bytes.fromint(new_ptr)),
                Op.DUP2(),
                Op.PUSH2(Bytes.fromint(old_ptr)),
                Op.EQ(),
                Op.PUSH2(Bytes.fromint(routing_exit_ptr)),
                Op.JUMPI(),
                Op.POP(),
            ]
        )
    routing_bytecode += Bytecode([Op.INVALID()])
    contract_bytecode += routing_bytecode
    offset += routing_bytecode.byte_length()

    for idx in routing_push_idxs:
        contract_bytecode[idx].set_data(Bytes.fromint(routing_ptr))

    constructor_bytecode[constructor_length_idx].set_data(
        Bytes.fromint(len(main_code_bytes) + offset)
    )

    full_code_bytes = (
        constructor_bytecode.bytes() + contract_bytecode.bytes() + metadata_bytes
    )
    assert (
        len(full_code_bytes)
        == constructor_bytecode.byte_length() + len(main_code_bytes) + offset
    )

    print(full_code_bytes)


def create_aa_bytecode(entrypoint):
    assert len(entrypoint) == 20
    return Bytecode(
        [
            Op.CALLER(),
            Op.PUSH20(entrypoint),
            Op.EQ(),
            Op.PUSH1(Bytes([0x1E])),
            Op.JUMPI(),
            Op.PUSH1(Bytes.zero(1)),
            Op.DUP1(),
            Op.REVERT(),
            Op.JUMPDEST(),
        ]
    )


if __name__ == "__main__":
    main()
