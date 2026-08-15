"""
Constants mirrored from YARA 4.5.8 headers.

Sources (VirusTotal/yara @ v4.5.8):
  libyara/include/yara/arena.h     -> YR_ARENA_FILE_VERSION
  libyara/include/yara/compiler.h  -> buffer (section) ids
  libyara/include/yara/types.h     -> rule/string/meta flags, struct layouts
  libyara/include/yara/exec.h      -> VM opcodes
  libyara/include/yara/re.h        -> regexp bytecode opcodes

Do not hand-edit values here without re-checking them against the header of
the YARA version you are targeting. `tools/check_constants.py` diffs this
module against a checked-out YARA tree.
"""

from enum import IntEnum, IntFlag

# --------------------------------------------------------------------------
# Arena container
# --------------------------------------------------------------------------

ARENA_MAGIC = b"YARA"

#: Arena file version -> range of YARA releases known to emit it.
#: 21 has been stable since 4.3.0 (the arena rewrite) through 4.5.8.
SUPPORTED_ARENA_VERSIONS = {21}

#: Arena versions we recognise but cannot parse (the pre-4.3 flat-arena
#: format that the original yaradec targeted).
LEGACY_ARENA_VERSIONS = {
    11: "YARA 3.x",
    12: "YARA 3.x",
    13: "YARA 3.11",
    14: "YARA 4.0",
    15: "YARA 4.0",
    16: "YARA 4.1",
    17: "YARA 4.1",
    18: "YARA 4.2",
    19: "YARA 4.2",
    20: "YARA 4.2",
}

NULL_REF = (0xFFFFFFFF, 0xFFFFFFFF)


class Section(IntEnum):
    """Arena buffer ids -- libyara/include/yara/compiler.h"""

    NAMESPACES_TABLE = 0
    RULES_TABLE = 1
    METAS_TABLE = 2
    STRINGS_TABLE = 3
    EXTERNAL_VARIABLES_TABLE = 4
    SZ_POOL = 5
    CODE_SECTION = 6
    RE_CODE_SECTION = 7
    AC_TRANSITION_TABLE = 8
    AC_STATE_MATCHES_TABLE = 9
    AC_STATE_MATCHES_POOL = 10
    SUMMARY_SECTION = 11


NUM_SECTIONS = 12

# --------------------------------------------------------------------------
# Struct sizes (pack(8), with DECLARE_REFERENCE unions forced to 8 bytes)
# Verified empirically against compiled output, see tests/test_layout.py
# --------------------------------------------------------------------------

SIZEOF_RULE = 56
SIZEOF_STRING = 56
SIZEOF_META = 32
SIZEOF_NAMESPACE = 16
SIZEOF_SUMMARY = 12
SIZEOF_EXTERNAL_VARIABLE = 24


# --------------------------------------------------------------------------
# Flags
# --------------------------------------------------------------------------


class RuleFlags(IntFlag):
    PRIVATE = 0x01
    GLOBAL = 0x02
    NULL = 0x04
    DISABLED = 0x08


class StringFlags(IntFlag):
    REFERENCED = 0x01
    HEXADECIMAL = 0x02
    NO_CASE = 0x04
    ASCII = 0x08
    WIDE = 0x10
    REGEXP = 0x20
    FAST_REGEXP = 0x40
    FULL_WORD = 0x80
    ANONYMOUS = 0x100
    SINGLE_MATCH = 0x200
    LITERAL = 0x400
    FITS_IN_ATOM = 0x800
    LAST_IN_RULE = 0x1000
    CHAIN_PART = 0x2000
    CHAIN_TAIL = 0x4000
    FIXED_OFFSET = 0x8000
    GREEDY_REGEXP = 0x10000
    DOT_ALL = 0x20000
    DISABLED = 0x40000
    XOR = 0x80000
    PRIVATE = 0x100000
    BASE64 = 0x200000
    BASE64_WIDE = 0x400000


class MetaType(IntEnum):
    INTEGER = 1
    STRING = 2
    BOOLEAN = 3


META_FLAGS_LAST_IN_RULE = 1


# --------------------------------------------------------------------------
# VM opcodes -- libyara/include/yara/exec.h
# --------------------------------------------------------------------------

_OP_EQ, _OP_NEQ, _OP_LT, _OP_GT, _OP_LE, _OP_GE = 0, 1, 2, 3, 4, 5
_OP_ADD, _OP_SUB, _OP_MUL, _OP_DIV, _OP_MINUS = 6, 7, 8, 9, 10

OP_INT_BEGIN = 100
OP_DBL_BEGIN = 120
OP_STR_BEGIN = 140


class Op(IntEnum):
    ERROR = 0
    AND = 1
    OR = 2
    NOT = 3
    BITWISE_NOT = 4
    BITWISE_AND = 5
    BITWISE_OR = 6
    BITWISE_XOR = 7
    SHL = 8
    SHR = 9
    MOD = 10
    INT_TO_DBL = 11
    STR_TO_BOOL = 12
    PUSH = 13
    POP = 14
    CALL = 15
    OBJ_LOAD = 16
    OBJ_VALUE = 17
    OBJ_FIELD = 18
    INDEX_ARRAY = 19
    COUNT = 20
    LENGTH = 21
    FOUND = 22
    FOUND_AT = 23
    FOUND_IN = 24
    OFFSET = 25
    OF = 26
    PUSH_RULE = 27
    INIT_RULE = 28
    MATCH_RULE = 29
    INCR_M = 30
    CLEAR_M = 31
    ADD_M = 32
    POP_M = 33
    PUSH_M = 34
    SET_M = 35
    SWAPUNDEF = 36
    FILESIZE = 37
    ENTRYPOINT = 38
    UNUSED = 39
    MATCHES = 40
    IMPORT = 41
    LOOKUP_DICT = 42
    JUNDEF = 43
    JUNDEF_P = 44
    JNUNDEF = 45
    JNUNDEF_P = 46
    JFALSE = 47
    JFALSE_P = 48
    JTRUE = 49
    JTRUE_P = 50
    JL_P = 51
    JLE_P = 52
    ITER_NEXT = 53
    ITER_START_ARRAY = 54
    ITER_START_DICT = 55
    ITER_START_INT_RANGE = 56
    ITER_START_INT_ENUM = 57
    ITER_START_STRING_SET = 58
    ITER_CONDITION = 59
    ITER_END = 60
    JZ = 61
    JZ_P = 62
    PUSH_8 = 63
    PUSH_16 = 64
    PUSH_32 = 65
    PUSH_U = 66
    CONTAINS = 67
    STARTSWITH = 68
    ENDSWITH = 69
    ICONTAINS = 70
    ISTARTSWITH = 71
    IENDSWITH = 72
    IEQUALS = 73
    OF_PERCENT = 74
    OF_FOUND_IN = 75
    COUNT_IN = 76
    DEFINED = 77
    ITER_START_TEXT_STRING_SET = 78
    OF_FOUND_AT = 79

    INT_EQ = OP_INT_BEGIN + _OP_EQ
    INT_NEQ = OP_INT_BEGIN + _OP_NEQ
    INT_LT = OP_INT_BEGIN + _OP_LT
    INT_GT = OP_INT_BEGIN + _OP_GT
    INT_LE = OP_INT_BEGIN + _OP_LE
    INT_GE = OP_INT_BEGIN + _OP_GE
    INT_ADD = OP_INT_BEGIN + _OP_ADD
    INT_SUB = OP_INT_BEGIN + _OP_SUB
    INT_MUL = OP_INT_BEGIN + _OP_MUL
    INT_DIV = OP_INT_BEGIN + _OP_DIV
    INT_MINUS = OP_INT_BEGIN + _OP_MINUS

    DBL_EQ = OP_DBL_BEGIN + _OP_EQ
    DBL_NEQ = OP_DBL_BEGIN + _OP_NEQ
    DBL_LT = OP_DBL_BEGIN + _OP_LT
    DBL_GT = OP_DBL_BEGIN + _OP_GT
    DBL_LE = OP_DBL_BEGIN + _OP_LE
    DBL_GE = OP_DBL_BEGIN + _OP_GE
    DBL_ADD = OP_DBL_BEGIN + _OP_ADD
    DBL_SUB = OP_DBL_BEGIN + _OP_SUB
    DBL_MUL = OP_DBL_BEGIN + _OP_MUL
    DBL_DIV = OP_DBL_BEGIN + _OP_DIV
    DBL_MINUS = OP_DBL_BEGIN + _OP_MINUS

    STR_EQ = OP_STR_BEGIN + _OP_EQ
    STR_NEQ = OP_STR_BEGIN + _OP_NEQ
    STR_LT = OP_STR_BEGIN + _OP_LT
    STR_GT = OP_STR_BEGIN + _OP_GT
    STR_LE = OP_STR_BEGIN + _OP_LE
    STR_GE = OP_STR_BEGIN + _OP_GE

    # Integer-reading functions, OP_READ_INT (240) + offset.
    INT8 = 240
    INT16 = 241
    INT32 = 242
    UINT8 = 243
    UINT16 = 244
    UINT32 = 245
    INT8BE = 246
    INT16BE = 247
    INT32BE = 248
    UINT8BE = 249
    UINT16BE = 250
    UINT32BE = 251

    NOP = 254
    HALT = 255


#: Operand encoding per opcode, verified by scanning the ``ip +=`` advancement
#: in each ``case`` of ``yr_execute_code`` (libyara/exec.c @ v4.5.8).
#:
#:   "u64"      -- 8-byte inline operand (arena ref, memory slot, or immediate)
#:   "u8"/"u16"/"u32" -- immediate of that width
#:   "jmp"      -- int32 offset RELATIVE TO THE OPCODE BYTE (not an absolute
#:                 address, and not 8 bytes -- this is the single biggest
#:                 difference from the YARA 3.x encoding the original yaradec
#:                 assumed)
#:   "jmp+u32"  -- int32 jump offset followed by a uint32 (OP_INIT_RULE only)
OPERANDS = {
    Op.PUSH: "u64",
    Op.PUSH_8: "u8",
    Op.PUSH_16: "u16",
    Op.PUSH_32: "u32",
    Op.CLEAR_M: "u64",
    Op.ADD_M: "u64",
    Op.INCR_M: "u64",
    Op.PUSH_M: "u64",
    Op.POP_M: "u64",
    Op.SET_M: "u64",
    Op.SWAPUNDEF: "u64",
    Op.PUSH_RULE: "u64",
    Op.MATCH_RULE: "u64",
    Op.OBJ_LOAD: "u64",
    Op.OBJ_FIELD: "u64",
    Op.CALL: "u64",
    Op.IMPORT: "u64",
    Op.INT_TO_DBL: "u64",
    Op.OF: "u64",          # OF and OF_PERCENT share a fall-through body
    Op.OF_PERCENT: "u64",  # in exec.c; both read a u64 (OF_STRING_SET/OF_RULE_SET)
    Op.INIT_RULE: "jmp+u32",
    Op.JNUNDEF: "jmp",
    Op.JUNDEF: "jmp",
    Op.JUNDEF_P: "jmp",
    Op.JNUNDEF_P: "jmp",
    Op.JL_P: "jmp",
    Op.JLE_P: "jmp",
    Op.JTRUE: "jmp",
    Op.JTRUE_P: "jmp",
    Op.JFALSE: "jmp",
    Op.JFALSE_P: "jmp",
    Op.JZ: "jmp",
    Op.JZ_P: "jmp",
}

#: Width in bytes of each operand kind, excluding the opcode byte itself.
OPERAND_WIDTH = {
    "u8": 1,
    "u16": 2,
    "u32": 4,
    "u64": 8,
    "jmp": 4,
    "jmp+u32": 8,
}

#: Opcodes that can transfer control somewhere other than the next instruction.
JUMP_OPS = {op for op, kind in OPERANDS.items() if kind.startswith("jmp")}


# --------------------------------------------------------------------------
# Regexp bytecode -- libyara/include/yara/re.h
# --------------------------------------------------------------------------


class ReOp(IntEnum):
    ANY = 0xA0
    LITERAL = 0xA2
    MASKED_LITERAL = 0xA4
    CLASS = 0xA5
    WORD_CHAR = 0xA7
    NON_WORD_CHAR = 0xA8
    SPACE = 0xA9
    NON_SPACE = 0xAA
    DIGIT = 0xAB
    NON_DIGIT = 0xAC
    MATCH = 0xAD
    NOT_LITERAL = 0xAE
    MASKED_NOT_LITERAL = 0xAF

    MATCH_AT_END = 0xB0
    MATCH_AT_START = 0xB1
    WORD_BOUNDARY = 0xB2
    NON_WORD_BOUNDARY = 0xB3
    REPEAT_ANY_GREEDY = 0xB4
    REPEAT_ANY_UNGREEDY = 0xB5

    SPLIT_A = 0xC0
    SPLIT_B = 0xC1
    JUMP = 0xC2
    REPEAT_START_GREEDY = 0xC3
    REPEAT_END_GREEDY = 0xC4
    REPEAT_START_UNGREEDY = 0xC5
    REPEAT_END_UNGREEDY = 0xC6


RE_FLAGS_FAST_REGEXP = 0x02
RE_FLAGS_BACKWARDS = 0x04
RE_FLAGS_EXHAUSTIVE = 0x08
RE_FLAGS_WIDE = 0x10
RE_FLAGS_NO_CASE = 0x20
RE_FLAGS_SCAN = 0x40
RE_FLAGS_DOT_ALL = 0x80
RE_FLAGS_GREEDY = 0x100
RE_FLAGS_UNGREEDY = 0x200


#: Source-level name for each integer-reading opcode.
READ_INT_NAMES = {
    Op.INT8: "int8", Op.INT16: "int16", Op.INT32: "int32",
    Op.UINT8: "uint8", Op.UINT16: "uint16", Op.UINT32: "uint32",
    Op.INT8BE: "int8be", Op.INT16BE: "int16be", Op.INT32BE: "int32be",
    Op.UINT8BE: "uint8be", Op.UINT16BE: "uint16be", Op.UINT32BE: "uint32be",
}
