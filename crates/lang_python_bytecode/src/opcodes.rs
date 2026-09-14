//! CPython bytecode opcode table (verified against a real `python3.9`
//! interpreter's `dis.opmap`/`dis.hasconst`/`dis.hasname`/`dis.haslocal`/
//! `dis.hasfree`/`dis.hasjrel`/`dis.hasjabs`/`dis.hascompare` in this
//! environment). Opcode *numbers* for the common instructions modeled here
//! have been stable across CPython 3.6–3.9 and remain so in 3.10 (3.10 adds
//! a handful of new high-numbered opcodes and changes jump-oparg *units*,
//! not the numbers below); only 3.9 was checked against a live interpreter.

pub const EXTENDED_ARG: u8 = 144;
/// The opcode name for every instruction this frontend gives specific
/// meaning to. An opcode not listed here still decodes (as `"UNKNOWN_n"`),
/// so a program using it still produces valid — if less precise — IR: the
/// generic fallback in `crate::lower` treats an unrecognized instruction as
/// an opaque, zero-effect no-op rather than failing the whole method.
pub fn opcode_name(code: u8) -> &'static str {
    match code {
        1 => "POP_TOP",
        2 => "ROT_TWO",
        3 => "ROT_THREE",
        4 => "DUP_TOP",
        5 => "DUP_TOP_TWO",
        6 => "ROT_FOUR",
        9 => "NOP",
        10 => "UNARY_POSITIVE",
        11 => "UNARY_NEGATIVE",
        12 => "UNARY_NOT",
        15 => "UNARY_INVERT",
        16 => "BINARY_MATRIX_MULTIPLY",
        17 => "INPLACE_MATRIX_MULTIPLY",
        19 => "BINARY_POWER",
        20 => "BINARY_MULTIPLY",
        22 => "BINARY_MODULO",
        23 => "BINARY_ADD",
        24 => "BINARY_SUBTRACT",
        25 => "BINARY_SUBSCR",
        26 => "BINARY_FLOOR_DIVIDE",
        27 => "BINARY_TRUE_DIVIDE",
        28 => "INPLACE_FLOOR_DIVIDE",
        29 => "INPLACE_TRUE_DIVIDE",
        48 => "RERAISE",
        49 => "WITH_EXCEPT_START",
        50 => "GET_AITER",
        51 => "GET_ANEXT",
        52 => "BEFORE_ASYNC_WITH",
        54 => "END_ASYNC_FOR",
        55 => "INPLACE_ADD",
        56 => "INPLACE_SUBTRACT",
        57 => "INPLACE_MULTIPLY",
        59 => "INPLACE_MODULO",
        60 => "STORE_SUBSCR",
        61 => "DELETE_SUBSCR",
        62 => "BINARY_LSHIFT",
        63 => "BINARY_RSHIFT",
        64 => "BINARY_AND",
        65 => "BINARY_XOR",
        66 => "BINARY_OR",
        67 => "INPLACE_POWER",
        68 => "GET_ITER",
        69 => "GET_YIELD_FROM_ITER",
        70 => "PRINT_EXPR",
        71 => "LOAD_BUILD_CLASS",
        72 => "YIELD_FROM",
        73 => "GET_AWAITABLE",
        74 => "LOAD_ASSERTION_ERROR",
        75 => "INPLACE_LSHIFT",
        76 => "INPLACE_RSHIFT",
        77 => "INPLACE_AND",
        78 => "INPLACE_XOR",
        79 => "INPLACE_OR",
        82 => "LIST_TO_TUPLE",
        83 => "RETURN_VALUE",
        84 => "IMPORT_STAR",
        85 => "SETUP_ANNOTATIONS",
        86 => "YIELD_VALUE",
        87 => "POP_BLOCK",
        89 => "POP_EXCEPT",
        90 => "STORE_NAME",
        91 => "DELETE_NAME",
        92 => "UNPACK_SEQUENCE",
        93 => "FOR_ITER",
        94 => "UNPACK_EX",
        95 => "STORE_ATTR",
        96 => "DELETE_ATTR",
        97 => "STORE_GLOBAL",
        98 => "DELETE_GLOBAL",
        100 => "LOAD_CONST",
        101 => "LOAD_NAME",
        102 => "BUILD_TUPLE",
        103 => "BUILD_LIST",
        104 => "BUILD_SET",
        105 => "BUILD_MAP",
        106 => "LOAD_ATTR",
        107 => "COMPARE_OP",
        108 => "IMPORT_NAME",
        109 => "IMPORT_FROM",
        110 => "JUMP_FORWARD",
        111 => "JUMP_IF_FALSE_OR_POP",
        112 => "JUMP_IF_TRUE_OR_POP",
        113 => "JUMP_ABSOLUTE",
        114 => "POP_JUMP_IF_FALSE",
        115 => "POP_JUMP_IF_TRUE",
        116 => "LOAD_GLOBAL",
        117 => "IS_OP",
        118 => "CONTAINS_OP",
        121 => "JUMP_IF_NOT_EXC_MATCH",
        122 => "SETUP_FINALLY",
        124 => "LOAD_FAST",
        125 => "STORE_FAST",
        126 => "DELETE_FAST",
        130 => "RAISE_VARARGS",
        131 => "CALL_FUNCTION",
        132 => "MAKE_FUNCTION",
        133 => "BUILD_SLICE",
        135 => "LOAD_CLOSURE",
        136 => "LOAD_DEREF",
        137 => "STORE_DEREF",
        138 => "DELETE_DEREF",
        141 => "CALL_FUNCTION_KW",
        142 => "CALL_FUNCTION_EX",
        143 => "SETUP_WITH",
        144 => "EXTENDED_ARG",
        145 => "LIST_APPEND",
        146 => "SET_ADD",
        147 => "MAP_ADD",
        148 => "LOAD_CLASSDEREF",
        154 => "SETUP_ASYNC_WITH",
        155 => "FORMAT_VALUE",
        156 => "BUILD_CONST_KEY_MAP",
        157 => "BUILD_STRING",
        160 => "LOAD_METHOD",
        161 => "CALL_METHOD",
        162 => "LIST_EXTEND",
        163 => "SET_UPDATE",
        164 => "DICT_MERGE",
        165 => "DICT_UPDATE",
        other => Box::leak(format!("UNKNOWN_{other}").into_boxed_str()),
    }
}





pub fn has_jrel(name: &str) -> bool {
    matches!(name, "FOR_ITER" | "JUMP_FORWARD" | "SETUP_FINALLY" | "SETUP_WITH" | "SETUP_ASYNC_WITH")
}

pub fn has_jabs(name: &str) -> bool {
    matches!(name, "JUMP_IF_FALSE_OR_POP" | "JUMP_IF_TRUE_OR_POP" | "JUMP_ABSOLUTE" | "POP_JUMP_IF_FALSE" | "POP_JUMP_IF_TRUE" | "JUMP_IF_NOT_EXC_MATCH")
}

#[derive(Clone, Debug)]
pub struct RawInstr {
    /// Byte offset of this instruction's opcode byte (the `EXTENDED_ARG`
    /// prefix bytes, if any, are folded into `oparg` and do not get their
    /// own `RawInstr` — matching how `dis` presents one logical instruction
    /// per `EXTENDED_ARG` chain).
    pub offset: u32,
    pub name: &'static str,
    pub oparg: u32,
    /// Total byte length of this instruction including any `EXTENDED_ARG`
    /// prefixes, so the caller can compute the next instruction's offset
    /// and (for `has_jrel`) the relative-jump base.
    pub size: u32,
}

/// Decodes one code object's raw bytecode into a flat instruction list,
/// folding `EXTENDED_ARG` prefixes into the following instruction's oparg
/// (each 2-byte instruction contributes 8 more low bits: `arg = arg << 8 |
/// byte`).
pub fn decode_instructions(code: &[u8]) -> Vec<RawInstr> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 1 < code.len() {
        let start = i;
        let mut arg: u32 = 0;
        loop {
            let op = code[i];
            let byte_arg = code[i + 1];
            i += 2;
            if op == EXTENDED_ARG {
                arg = (arg << 8) | byte_arg as u32;
                if i + 1 >= code.len() {
                    break;
                }
                continue;
            }
            arg = (arg << 8) | byte_arg as u32;
            out.push(RawInstr { offset: start as u32, name: opcode_name(op), oparg: arg, size: (i - start) as u32 });
            break;
        }
    }
    out
}

/// The absolute byte-offset jump target for a `has_jrel`/`has_jabs`
/// instruction, accounting for 3.10's switch from raw byte offsets to
/// 2-byte "code unit" counts.
pub fn jump_target(instr: &RawInstr, jump_in_code_units: bool) -> Option<u32> {
    let raw = if jump_in_code_units { instr.oparg * 2 } else { instr.oparg };
    if has_jrel(instr.name) {
        Some(instr.offset + instr.size + raw)
    } else if has_jabs(instr.name) {
        Some(raw)
    } else {
        None
    }
}
