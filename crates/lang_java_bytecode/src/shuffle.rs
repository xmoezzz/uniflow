//! JVM operand-stack shuffle instructions (`pop`/`pop2`, `dup*`, `swap`),
//! shared verbatim between the entry-shape pre-pass (`cfg.rs`, `T = ()`) and
//! the real value-construction pass (`lower.rs`, `T = ValueId`). These
//! instructions never inspect or produce payload data — they only
//! rearrange/duplicate/remove stack entries based on which entries are
//! "wide" (category-2: `long`/`double`) — so one generic implementation
//! covers both passes and both passes are guaranteed to agree on shape.

use anyhow::{anyhow, Result};

/// One logical operand-stack entry: a payload of type `T` plus whether it
/// occupies a wide (category-2) JVM stack slot.
pub type Entry<T> = (T, bool);

fn segment_len<T>(stack: &[Entry<T>], skip_from_top: usize) -> Result<usize> {
    let idx = stack
        .len()
        .checked_sub(1 + skip_from_top)
        .ok_or_else(|| anyhow!("operand stack underflow while sizing a dup segment"))?;
    Ok(if stack[idx].1 { 1 } else { 2 })
}

/// `dup_insert(stack, top_count, below_count)`: pops `top_count + below_count`
/// entries (the top `top_count` form the segment being duplicated; the
/// `below_count` beneath them are left untouched but temporarily removed to
/// simplify reinsertion), then pushes `[copy of top segment, original below
/// segment, original top segment]` — i.e. inserts a copy of the top segment
/// immediately below the original below segment. This single shape covers
/// every `dup_x1`/`dup_x2`/`dup2_x1`/`dup2_x2` form; only how `top_count`
/// and `below_count` are derived differs per opcode (see `cfg.rs`/`lower.rs`).
fn dup_insert<T: Clone>(stack: &mut Vec<Entry<T>>, top_count: usize, below_count: usize) -> Result<()> {
    let total = top_count + below_count;
    let start = stack
        .len()
        .checked_sub(total)
        .ok_or_else(|| anyhow!("operand stack underflow during dup"))?;
    let segment = stack[start..].to_vec(); // [below..., top...] in original order
    let top_part = segment[below_count..].to_vec();
    stack.truncate(start);
    stack.extend(top_part);
    stack.extend(segment);
    Ok(())
}

pub fn pop(stack: &mut Vec<Entry<impl Clone>>, count: u8) -> Result<()> {
    match count {
        1 => {
            stack
                .pop()
                .ok_or_else(|| anyhow!("operand stack underflow on pop"))?;
        }
        2 => {
            let wide = stack
                .last()
                .ok_or_else(|| anyhow!("operand stack underflow on pop2"))?
                .1;
            let n = if wide { 1 } else { 2 };
            for _ in 0..n {
                stack
                    .pop()
                    .ok_or_else(|| anyhow!("operand stack underflow on pop2"))?;
            }
        }
        other => return Err(anyhow!("invalid pop width {other}")),
    }
    Ok(())
}

pub fn dup<T: Clone>(stack: &mut Vec<Entry<T>>) -> Result<()> {
    let top = stack
        .last()
        .cloned()
        .ok_or_else(|| anyhow!("operand stack underflow on dup"))?;
    stack.push(top);
    Ok(())
}

pub fn dup_x1<T: Clone>(stack: &mut Vec<Entry<T>>) -> Result<()> {
    dup_insert(stack, 1, 1)
}

pub fn dup_x2<T: Clone>(stack: &mut Vec<Entry<T>>) -> Result<()> {
    let below = segment_len(stack, 1)?;
    dup_insert(stack, 1, below)
}

pub fn dup2<T: Clone>(stack: &mut Vec<Entry<T>>) -> Result<()> {
    let top = segment_len(stack, 0)?;
    let start = stack
        .len()
        .checked_sub(top)
        .ok_or_else(|| anyhow!("operand stack underflow on dup2"))?;
    let clone = stack[start..].to_vec();
    stack.extend(clone);
    Ok(())
}

pub fn dup2_x1<T: Clone>(stack: &mut Vec<Entry<T>>) -> Result<()> {
    let top = segment_len(stack, 0)?;
    dup_insert(stack, top, 1)
}

pub fn dup2_x2<T: Clone>(stack: &mut Vec<Entry<T>>) -> Result<()> {
    let top = segment_len(stack, 0)?;
    let below = segment_len(stack, top)?;
    dup_insert(stack, top, below)
}

pub fn swap<T>(stack: &mut Vec<Entry<T>>) -> Result<()> {
    let len = stack.len();
    if len < 2 {
        return Err(anyhow!("operand stack underflow on swap"));
    }
    stack.swap(len - 1, len - 2);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stack(entries: &[(i32, bool)]) -> Vec<Entry<i32>> {
        entries.to_vec()
    }

    #[test]
    fn dup_x1_inserts_below_the_pair() {
        let mut s = stack(&[(1, false), (2, false)]);
        dup_x1(&mut s).unwrap();
        assert_eq!(s, vec![(2, false), (1, false), (2, false)]);
    }

    #[test]
    fn dup_x2_form1_all_narrow() {
        let mut s = stack(&[(3, false), (2, false), (1, false)]);
        dup_x2(&mut s).unwrap();
        assert_eq!(
            s,
            vec![(1, false), (3, false), (2, false), (1, false)]
        );
    }

    #[test]
    fn dup_x2_form2_wide_below() {
        let mut s = stack(&[(2, true), (1, false)]);
        dup_x2(&mut s).unwrap();
        assert_eq!(s, vec![(1, false), (2, true), (1, false)]);
    }

    #[test]
    fn dup2_form1_two_narrow() {
        let mut s = stack(&[(2, false), (1, false)]);
        dup2(&mut s).unwrap();
        assert_eq!(s, vec![(2, false), (1, false), (2, false), (1, false)]);
    }

    #[test]
    fn dup2_form2_single_wide() {
        let mut s = stack(&[(1, true)]);
        dup2(&mut s).unwrap();
        assert_eq!(s, vec![(1, true), (1, true)]);
    }

    #[test]
    fn pop2_removes_one_wide_or_two_narrow() {
        let mut wide = stack(&[(1, true)]);
        pop(&mut wide, 2).unwrap();
        assert!(wide.is_empty());

        let mut narrow = stack(&[(1, false), (2, false)]);
        pop(&mut narrow, 2).unwrap();
        assert!(narrow.is_empty());
    }

    #[test]
    fn swap_exchanges_top_two() {
        let mut s = stack(&[(1, false), (2, false)]);
        swap(&mut s).unwrap();
        assert_eq!(s, vec![(2, false), (1, false)]);
    }
}
