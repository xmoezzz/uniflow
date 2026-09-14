//! JVM instruction decoding (JVMS §6.5, chapter "The Java Virtual Machine
//! Instruction Set"). Semantically related opcodes (e.g. every `Txstore`
//! family member, every `if_icmp<cond>` member) are folded into one
//! `OpKind` variant parameterized by the operand/condition, since the
//! stack-machine lowering in `lower.rs` treats them identically regardless
//! of the operand's JVM primitive type.

use crate::constant_pool::ConstantPool;
use crate::descriptor::JvmType;
use crate::version::{check_opcode, ClassVersion};
use anyhow::{bail, Result};
use uniflow_ir::ComparisonOp;

#[derive(Clone, Debug)]
pub enum LdcValue {
    Int(i64),
    Float(f64),
    String(String),
    Class(String),
    /// `MethodHandle`/`MethodType`/`Dynamic` constants loaded via `ldc*`.
    /// Rare outside of reflective metaprogramming; taint-tracked as an
    /// opaque value.
    Opaque,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberKind {
    Static,
    Instance,
    Interface,
}

#[derive(Clone, Debug)]
pub struct MemberRef {
    pub class: String,
    pub name: String,
    pub descriptor: String,
}

#[derive(Clone, Debug)]
pub enum OpKind {
    Nop,
    ConstNull,
    /// `wide` is true only for `ldc2_w` (long/double), which pushes a
    /// category-2 value; `lower.rs` needs this to simulate `dup2`/`pop2`
    /// correctly.
    Ldc { value: LdcValue, wide: bool },
    /// `wide` is true for `lload`/`dload` (category-2 locals).
    Load { slot: u16, wide: bool },
    Store { slot: u16 },
    /// `xaload`: array element load. `wide` is true for `laload`/`daload`.
    ArrayLoad { wide: bool },
    /// `xastore`: array element store; the popped value's own category is
    /// already known from the simulated stack, so no flag is needed here.
    ArrayStore,
    Pop(u8),
    Dup,
    DupX1,
    DupX2,
    Dup2,
    Dup2X1,
    Dup2X2,
    Swap,
    /// Any binary arithmetic/bitwise op (`iadd` .. `lxor`): pops two,
    /// pushes one.
    BinaryOp,
    /// `ineg`/`lneg`/`fneg`/`dneg`: pops one, pushes one.
    UnaryNeg,
    IInc { slot: u16, value: i32 },
    /// Any widening/narrowing numeric conversion (`i2l` .. `d2f`): pops
    /// one, pushes one. `to_wide` reflects the *target* type's category
    /// (`i2l`/`i2d`/`f2l`/`f2d`/`l2d` are category-2 results).
    Convert { to_wide: bool },
    /// `lcmp`/`fcmpl`/`fcmpg`/`dcmpl`/`dcmpg`: pops two, pushes an int.
    Compare,
    IfZero { cmp: ComparisonOp, target: u32 },
    IfCmp { cmp: ComparisonOp, target: u32 },
    IfNull { target: u32 },
    IfNonNull { target: u32 },
    Goto(u32),
    /// Deprecated `jsr`/`jsr_w`. Treated as an unconditional edge to the
    /// target for CFG purposes; the pushed return address is not modeled.
    Jsr(u32),
    /// Deprecated `ret`. Terminates the block with no known static
    /// successor (finally-subroutine epilogue); modeled as unreachable.
    Ret { slot: u16 },
    TableSwitch {
        default: u32,
        low: i32,
        targets: Vec<u32>,
    },
    LookupSwitch {
        default: u32,
        pairs: Vec<(i32, u32)>,
    },
    /// `return`/`ireturn`/.../`areturn`: `has_value` distinguishes `return`
    /// (void) from the rest.
    Return { has_value: bool },
    GetStatic(MemberRef),
    PutStatic(MemberRef),
    GetField(MemberRef),
    PutField(MemberRef),
    Invoke { member: MemberRef, kind: MemberKind },
    InvokeDynamic {
        bootstrap_index: u16,
        name: String,
        descriptor: String,
    },
    New { class: String },
    NewArray { element: JvmType },
    ANewArray { class: String },
    MultiANewArray { class: String, dims: u8 },
    ArrayLength,
    AThrow,
    CheckCast { class: String },
    InstanceOf { class: String },
    MonitorEnter,
    MonitorExit,
}

#[derive(Clone, Debug)]
pub struct RawInstr {
    pub offset: u32,
    pub size: u32,
    pub kind: OpKind,
}

fn newarray_type(atype: u8) -> Result<JvmType> {
    Ok(match atype {
        4 => JvmType::Boolean,
        5 => JvmType::Char,
        6 => JvmType::Float,
        7 => JvmType::Double,
        8 => JvmType::Byte,
        9 => JvmType::Short,
        10 => JvmType::Int,
        11 => JvmType::Long,
        other => bail!("unrecognized newarray atype {other}"),
    })
}

fn resolve_member(pool: &ConstantPool, index: u16) -> Result<MemberRef> {
    let (class, name, descriptor) = pool.member_ref(index)?;
    Ok(MemberRef {
        class,
        name,
        descriptor,
    })
}

fn ldc_value(pool: &ConstantPool, index: u16) -> Result<LdcValue> {
    Ok(match pool.entry(index)? {
        crate::constant_pool::ConstantPoolEntry::Integer(value) => LdcValue::Int(*value as i64),
        crate::constant_pool::ConstantPoolEntry::Float(value) => LdcValue::Float(*value as f64),
        crate::constant_pool::ConstantPoolEntry::Long(value) => LdcValue::Int(*value),
        crate::constant_pool::ConstantPoolEntry::Double(value) => LdcValue::Float(*value),
        crate::constant_pool::ConstantPoolEntry::String { .. } => {
            LdcValue::String(pool.string_value(index)?)
        }
        crate::constant_pool::ConstantPoolEntry::Class { .. } => {
            LdcValue::Class(pool.class_name(index)?)
        }
        _ => LdcValue::Opaque,
    })
}

/// Decodes one instruction (including any `wide`-modified form) starting at
/// `code[offset]`. `pool` resolves embedded constant-pool operands
/// immediately. Returns the decoded instruction; the caller advances by
/// `RawInstr::size`.
pub fn decode_one(
    code: &[u8],
    offset: usize,
    pool: &ConstantPool,
    version: ClassVersion,
) -> Result<RawInstr> {
    let start = offset;
    let opcode = *code
        .get(offset)
        .ok_or_else(|| anyhow::anyhow!("instruction offset {offset} out of range"))?;
    if let Err(message) = check_opcode(opcode, version) {
        bail!(message);
    }
    let mut pos = offset + 1;
    let u8_at = |pos: usize| -> Result<u8> {
        code.get(pos)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("truncated instruction at {pos}"))
    };
    let u16_at = |pos: usize| -> Result<u16> {
        Ok(((u8_at(pos)? as u16) << 8) | u8_at(pos + 1)? as u16)
    };
    let i16_at = |pos: usize| -> Result<i16> { Ok(u16_at(pos)? as i16) };
    let i32_at = |pos: usize| -> Result<i32> {
        let hi = u16_at(pos)? as u32;
        let lo = u16_at(pos + 2)? as u32;
        Ok(((hi << 16) | lo) as i32)
    };

    let kind = match opcode {
        0 => OpKind::Nop,
        1 => OpKind::ConstNull,
        2..=8 => OpKind::Ldc { value: LdcValue::Int(opcode as i64 - 3), wide: false }, // iconst_m1..iconst_5
        9 | 10 => OpKind::Ldc { value: LdcValue::Int((opcode - 9) as i64), wide: true }, // lconst_0/1
        11..=13 => OpKind::Ldc { value: LdcValue::Float((opcode - 11) as f64), wide: false }, // fconst_0..2
        14 | 15 => OpKind::Ldc { value: LdcValue::Float((opcode - 14) as f64), wide: true }, // dconst_0/1
        16 => {
            let value = u8_at(pos)? as i8 as i64;
            pos += 1;
            OpKind::Ldc { value: LdcValue::Int(value), wide: false }
        }
        17 => {
            let value = i16_at(pos)? as i64;
            pos += 2;
            OpKind::Ldc { value: LdcValue::Int(value), wide: false }
        }
        18 => {
            let index = u8_at(pos)? as u16;
            pos += 1;
            OpKind::Ldc { value: ldc_value(pool, index)?, wide: false }
        }
        19 => {
            let index = u16_at(pos)?;
            pos += 2;
            OpKind::Ldc { value: ldc_value(pool, index)?, wide: false }
        }
        20 => {
            let index = u16_at(pos)?;
            pos += 2;
            OpKind::Ldc { value: ldc_value(pool, index)?, wide: true }
        }
        21 | 23 | 25 => {
            // iload, fload, aload (narrow)
            let slot = u8_at(pos)? as u16;
            pos += 1;
            OpKind::Load { slot, wide: false }
        }
        22 | 24 => {
            // lload, dload (wide)
            let slot = u8_at(pos)? as u16;
            pos += 1;
            OpKind::Load { slot, wide: true }
        }
        26..=29 => OpKind::Load { slot: (opcode - 26) as u16, wide: false }, // iload_0..3
        30..=33 => OpKind::Load { slot: (opcode - 30) as u16, wide: true }, // lload_0..3
        34..=37 => OpKind::Load { slot: (opcode - 34) as u16, wide: false }, // fload_0..3
        38..=41 => OpKind::Load { slot: (opcode - 38) as u16, wide: true }, // dload_0..3
        42..=45 => OpKind::Load { slot: (opcode - 42) as u16, wide: false }, // aload_0..3
        46 | 48 | 50..=53 => OpKind::ArrayLoad { wide: false }, // iaload,faload,aaload,baload,caload,saload
        47 | 49 => OpKind::ArrayLoad { wide: true }, // laload, daload
        54..=58 => {
            let slot = u8_at(pos)? as u16;
            pos += 1;
            OpKind::Store { slot }
        }
        59..=62 => OpKind::Store { slot: (opcode - 59) as u16 }, // istore_0..3
        63..=66 => OpKind::Store { slot: (opcode - 63) as u16 }, // lstore_0..3
        67..=70 => OpKind::Store { slot: (opcode - 67) as u16 }, // fstore_0..3
        71..=74 => OpKind::Store { slot: (opcode - 71) as u16 }, // dstore_0..3
        75..=78 => OpKind::Store { slot: (opcode - 75) as u16 }, // astore_0..3
        79..=86 => OpKind::ArrayStore, // iastore..sastore
        87 => OpKind::Pop(1),
        88 => OpKind::Pop(2),
        89 => OpKind::Dup,
        90 => OpKind::DupX1,
        91 => OpKind::DupX2,
        92 => OpKind::Dup2,
        93 => OpKind::Dup2X1,
        94 => OpKind::Dup2X2,
        95 => OpKind::Swap,
        96..=115 => OpKind::BinaryOp, // iadd..drem
        116..=119 => OpKind::UnaryNeg, // ineg,lneg,fneg,dneg
        120..=131 => OpKind::BinaryOp, // ishl..lxor
        132 => {
            let slot = u8_at(pos)? as u16;
            let value = u8_at(pos + 1)? as i8 as i32;
            pos += 2;
            OpKind::IInc { slot, value }
        }
        133..=147 => OpKind::Convert {
            // i2l,i2d,l2d,f2l,f2d,d2l produce a category-2 (wide) result.
            to_wide: matches!(opcode, 133 | 135 | 138 | 140 | 141 | 143),
        },
        148..=152 => OpKind::Compare, // lcmp..dcmpg
        153..=158 => {
            let cmp = match opcode {
                153 => ComparisonOp::Eq,
                154 => ComparisonOp::Ne,
                155 => ComparisonOp::Lt,
                156 => ComparisonOp::Ge,
                157 => ComparisonOp::Gt,
                _ => ComparisonOp::Le,
            };
            let target = (start as i64 + i16_at(pos)? as i64) as u32;
            pos += 2;
            OpKind::IfZero { cmp, target }
        }
        159..=166 => {
            let cmp = match opcode {
                159 | 165 => ComparisonOp::Eq,
                160 | 166 => ComparisonOp::Ne,
                161 => ComparisonOp::Lt,
                162 => ComparisonOp::Ge,
                163 => ComparisonOp::Gt,
                _ => ComparisonOp::Le,
            };
            let target = (start as i64 + i16_at(pos)? as i64) as u32;
            pos += 2;
            OpKind::IfCmp { cmp, target }
        }
        167 => {
            let target = (start as i64 + i16_at(pos)? as i64) as u32;
            pos += 2;
            OpKind::Goto(target)
        }
        168 => {
            let target = (start as i64 + i16_at(pos)? as i64) as u32;
            pos += 2;
            OpKind::Jsr(target)
        }
        169 => {
            let slot = u8_at(pos)? as u16;
            pos += 1;
            OpKind::Ret { slot }
        }
        170 => {
            // tableswitch: padded to a 4-byte boundary from the instruction start.
            let mut cursor = start + 1;
            while (cursor - start) % 4 != 0 {
                cursor += 1;
            }
            let default = (start as i64 + i32_at(cursor)? as i64) as u32;
            let low = i32_at(cursor + 4)?;
            let high = i32_at(cursor + 8)?;
            let count = (high - low + 1).max(0) as usize;
            let mut targets = Vec::with_capacity(count);
            let mut target_cursor = cursor + 12;
            for _ in 0..count {
                targets.push((start as i64 + i32_at(target_cursor)? as i64) as u32);
                target_cursor += 4;
            }
            pos = target_cursor;
            OpKind::TableSwitch { default, low, targets }
        }
        171 => {
            let mut cursor = start + 1;
            while (cursor - start) % 4 != 0 {
                cursor += 1;
            }
            let default = (start as i64 + i32_at(cursor)? as i64) as u32;
            let npairs = i32_at(cursor + 4)? as usize;
            let mut pairs = Vec::with_capacity(npairs);
            let mut pair_cursor = cursor + 8;
            for _ in 0..npairs {
                let match_value = i32_at(pair_cursor)?;
                let target = (start as i64 + i32_at(pair_cursor + 4)? as i64) as u32;
                pairs.push((match_value, target));
                pair_cursor += 8;
            }
            pos = pair_cursor;
            OpKind::LookupSwitch { default, pairs }
        }
        172..=176 => OpKind::Return { has_value: true }, // ireturn..areturn
        177 => OpKind::Return { has_value: false },
        178 => {
            let index = u16_at(pos)?;
            pos += 2;
            OpKind::GetStatic(resolve_member(pool, index)?)
        }
        179 => {
            let index = u16_at(pos)?;
            pos += 2;
            OpKind::PutStatic(resolve_member(pool, index)?)
        }
        180 => {
            let index = u16_at(pos)?;
            pos += 2;
            OpKind::GetField(resolve_member(pool, index)?)
        }
        181 => {
            let index = u16_at(pos)?;
            pos += 2;
            OpKind::PutField(resolve_member(pool, index)?)
        }
        182 => {
            let index = u16_at(pos)?;
            pos += 2;
            OpKind::Invoke {
                member: resolve_member(pool, index)?,
                kind: MemberKind::Instance,
            }
        }
        183 => {
            let index = u16_at(pos)?;
            pos += 2;
            OpKind::Invoke {
                member: resolve_member(pool, index)?,
                kind: MemberKind::Instance,
            }
        }
        184 => {
            let index = u16_at(pos)?;
            pos += 2;
            OpKind::Invoke {
                member: resolve_member(pool, index)?,
                kind: MemberKind::Static,
            }
        }
        185 => {
            let index = u16_at(pos)?;
            let _count = u8_at(pos + 2)?;
            let _zero = u8_at(pos + 3)?;
            pos += 4;
            OpKind::Invoke {
                member: resolve_member(pool, index)?,
                kind: MemberKind::Interface,
            }
        }
        186 => {
            let index = u16_at(pos)?;
            let _zero1 = u8_at(pos + 2)?;
            let _zero2 = u8_at(pos + 3)?;
            pos += 4;
            let (bootstrap_index, name, descriptor) = pool.dynamic_ref(index)?;
            OpKind::InvokeDynamic {
                bootstrap_index,
                name,
                descriptor,
            }
        }
        187 => {
            let index = u16_at(pos)?;
            pos += 2;
            OpKind::New {
                class: pool.class_name(index)?,
            }
        }
        188 => {
            let atype = u8_at(pos)?;
            pos += 1;
            OpKind::NewArray {
                element: newarray_type(atype)?,
            }
        }
        189 => {
            let index = u16_at(pos)?;
            pos += 2;
            OpKind::ANewArray {
                class: pool.class_name(index)?,
            }
        }
        190 => OpKind::ArrayLength,
        191 => OpKind::AThrow,
        192 => {
            let index = u16_at(pos)?;
            pos += 2;
            OpKind::CheckCast {
                class: pool.class_name(index)?,
            }
        }
        193 => {
            let index = u16_at(pos)?;
            pos += 2;
            OpKind::InstanceOf {
                class: pool.class_name(index)?,
            }
        }
        194 => OpKind::MonitorEnter,
        195 => OpKind::MonitorExit,
        196 => return decode_wide(code, start, pos),
        197 => {
            let index = u16_at(pos)?;
            let dims = u8_at(pos + 2)?;
            pos += 3;
            OpKind::MultiANewArray {
                class: pool.class_name(index)?,
                dims,
            }
        }
        198 => {
            let target = (start as i64 + i16_at(pos)? as i64) as u32;
            pos += 2;
            OpKind::IfNull { target }
        }
        199 => {
            let target = (start as i64 + i16_at(pos)? as i64) as u32;
            pos += 2;
            OpKind::IfNonNull { target }
        }
        200 => {
            let target = (start as i64 + i32_at(pos)? as i64) as u32;
            pos += 4;
            OpKind::Goto(target)
        }
        201 => {
            let target = (start as i64 + i32_at(pos)? as i64) as u32;
            pos += 4;
            OpKind::Jsr(target)
        }
        other => bail!("unsupported opcode {other} at offset {start}"),
    };
    Ok(RawInstr {
        offset: start as u32,
        size: (pos - start) as u32,
        kind,
    })
}

fn decode_wide(code: &[u8], start: usize, mut pos: usize) -> Result<RawInstr> {
    let modified = *code
        .get(pos)
        .ok_or_else(|| anyhow::anyhow!("truncated wide instruction at {pos}"))?;
    pos += 1;
    let u16_at = |code: &[u8], pos: usize| -> Result<u16> {
        let hi = *code
            .get(pos)
            .ok_or_else(|| anyhow::anyhow!("truncated wide operand"))? as u16;
        let lo = *code
            .get(pos + 1)
            .ok_or_else(|| anyhow::anyhow!("truncated wide operand"))? as u16;
        Ok((hi << 8) | lo)
    };
    let kind = match modified {
        21 | 23 | 25 => {
            let slot = u16_at(code, pos)?;
            pos += 2;
            OpKind::Load { slot, wide: false }
        }
        22 | 24 => {
            let slot = u16_at(code, pos)?;
            pos += 2;
            OpKind::Load { slot, wide: true }
        }
        54..=58 => {
            let slot = u16_at(code, pos)?;
            pos += 2;
            OpKind::Store { slot }
        }
        169 => {
            let slot = u16_at(code, pos)?;
            pos += 2;
            OpKind::Ret { slot }
        }
        132 => {
            let slot = u16_at(code, pos)?;
            let value = u16_at(code, pos + 2)? as i16 as i32;
            pos += 4;
            OpKind::IInc { slot, value }
        }
        other => bail!("unsupported wide-modified opcode {other} at offset {start}"),
    };
    Ok(RawInstr {
        offset: start as u32,
        size: (pos - start) as u32,
        kind,
    })
}
