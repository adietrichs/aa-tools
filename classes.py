import struct
from typing import List, Set, Type, TypeVar, Union

from opcodes import *

T = TypeVar("T")


class Bytecode:
    def __init__(self, elements: List["BytecodeElement"] = None):
        self.elements = elements if elements is not None else []

    def __len__(self):
        return len(self.elements)

    def __repr__(self):
        return f"[{' '.join([str(element) for element in self.elements])}]"

    def __iter__(self):
        return self.elements.__iter__()

    def __getitem__(
        self, item: Union[int, slice]
    ) -> Union["BytecodeElement", "Bytecode"]:
        return (
            self.elements[item] if type(item) is int else Bytecode(self.elements[item])
        )

    def __setitem__(self, key: int, value: "BytecodeElement"):
        self.elements[key] = value

    def __add__(self, other: "Bytecode"):
        return Bytecode(self.elements + other.elements)

    def __iadd__(self, other: "Bytecode"):
        self.elements += other.elements
        return self

    @classmethod
    def frombytes(cls: Type[T], _bytes: "Bytes", stop_opcodes: Set[Op] = {}) -> T:
        elements = []
        ptr = 0
        while ptr < len(_bytes):
            opcode = Op(_bytes[ptr])
            data = None
            if opcode in PUSH_OPCODES:
                data = _bytes[ptr + 1 : ptr + 1 + opcode.push_length()]
                ptr += opcode.push_length()
            elements.append(BytecodeElement(opcode, data=data))
            ptr += 1
            if opcode in stop_opcodes:
                break
        return cls(elements)

    def byte_length(self):
        return sum(len(element) for element in self.elements)

    def bytes(self):
        _bytes = Bytes()
        for element in self.elements:
            _bytes += element.bytes()
        return _bytes


class BytecodeElement:
    def __init__(self, opcode: Op, data: "Bytes" = None):
        self.opcode = opcode
        if opcode in PUSH_OPCODES:
            assert len(data) == opcode.push_length()
        else:
            assert data is None
        self.data = data

    def __len__(self):
        return 1 + (len(self.data) if self.data is not None else 0)

    def __repr__(self):
        return f"<{self.opcode.name}" + (
            f" {self.data}>" if self.data is not None else ">"
        )

    def set_data(self, data: "Bytes"):
        assert len(data) == len(self.data)
        self.data = data

    def bytes(self):
        _bytes = Bytes([self.opcode.value])
        if self.data is not None:
            _bytes += self.data
        return _bytes


class Bytes:
    def __init__(self, *args, **kwargs):
        self.bytes = bytes(*args, **kwargs)

    def __len__(self):
        return len(self.bytes)

    def __getitem__(self, item: Union[int, slice]) -> Union[int, "Bytes"]:
        return self.bytes[item] if type(item) is int else Bytes(self.bytes[item])

    def __add__(self, other: "Bytes"):
        return Bytes(self.bytes + other.bytes)

    def __iadd__(self, other: "Bytes"):
        self.bytes += other.bytes
        return self

    def __repr__(self):
        return f"0x{self.bytes.hex()}"

    @staticmethod
    def fromhex(hex: str) -> "Bytes":
        if hex.startswith("0x"):
            hex = hex[2:]
        return Bytes(bytes.fromhex(hex))

    @staticmethod
    def fromint(_int: int) -> "Bytes":
        return Bytes(struct.pack(">H", _int))

    @staticmethod
    def zero(length: int) -> "Bytes":
        return Bytes([0x00] * length)

    def int(self) -> int:
        assert len(self) in (1, 2)
        return struct.unpack(">H", b"\x00" * (2 - len(self)) + self.bytes)[0]
