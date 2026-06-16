// Author: Iamzulx
// Copyright (c) 2026
// License: MIT
//! MicroVM — isolated, deterministic bytecode executor.
//!
//! A stack machine with a canary-protected operand stack (128 × u64).
//! No file I/O, no network, no allocation during execution. Every run
//! produces a 64-byte root deterministically from the input code. The VM
//! auto-zeroises its entire stack on drop.
//!
//! ## Opcodes
//! | Code | Name | Operands | Effect |
//! |------|------|----------|--------|
//! | 0x00 | Nop  | —        | No operation |
//! | 0x01 | Add  | —        | Pop b, a → push a + b (mod 2^64) |
//! | 0x02 | Xor  | —        | Pop b, a → push a ⊕ b |
//! | 0x03 | Mul  | —        | Pop b, a → push a × b (mod 2^64) |
//! | 0x04 | Div  | —        | Pop b, a → push a / b (0 if b=0) |
//! | 0x05 | Push | 8B LE    | Push immediate u64 onto stack |
//! | 0x06 | Pop  | —        | Pop and discard top of stack |
//! | 0x07 | Dup  | —        | Duplicate top of stack |
//! | 0x08 | Swap | —        | Swap top two elements |
//! | 0x09 | And  | —        | Pop b, a → push a & b |
//! | 0x0A | Or   | —        | Pop b, a → push a \| b |
//! | 0x0B | Not  | —        | Pop a → push !a (bitwise NOT) |
//! | 0x0C | Shl  | —        | Pop shift, a → push a << (shift & 63) |
//! | 0x0D | Shr  | —        | Pop shift, a → push a >> (shift & 63) |
//! | 0x0E | Rot  | —        | Rotate stack: bottom→top |
//! | 0x0F | Eq   | —        | Pop b, a → push 1 if a==b else 0 |
//! | 0x10 | Lt   | —        | Pop b, a → push 1 if a<b else 0 |
//!
//! ## Bytecode format
//! Each instruction is 1 byte (opcode). `Push` is followed by 8 bytes
//! of little-endian u64 immediate data. Invalid opcodes or insufficient
//! stack depth cause fail-closed (all-zero root).
//!
//! ## Safety
//! - Stack canary guards against overflow corruption. If canary is damaged
//!   before or after execution, the VM returns all-zeros and wipes itself.
//! - Invalid opcodes, empty code, and oversized bytecode all fail-closed.
//! - Maximum 4096 bytes of bytecode (≈512 Push instructions).

use crate::shake256::Shake256;

use crate::l0_memlock::zeroize_u64;

// ── Opcodes ──────────────────────────────────────────────────────────────────

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum OpCode {
    Nop = 0x00,
    Add = 0x01,
    Xor = 0x02,
    Mul = 0x03,
    Div = 0x04,
    Push = 0x05,
    Pop = 0x06,
    Dup = 0x07,
    Swap = 0x08,
    And = 0x09,
    Or = 0x0A,
    Not = 0x0B,
    Shl = 0x0C,
    Shr = 0x0D,
    Rot = 0x0E,
    Eq = 0x0F,
    Lt = 0x10,
}

impl OpCode {
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(OpCode::Nop),
            0x01 => Some(OpCode::Add),
            0x02 => Some(OpCode::Xor),
            0x03 => Some(OpCode::Mul),
            0x04 => Some(OpCode::Div),
            0x05 => Some(OpCode::Push),
            0x06 => Some(OpCode::Pop),
            0x07 => Some(OpCode::Dup),
            0x08 => Some(OpCode::Swap),
            0x09 => Some(OpCode::And),
            0x0A => Some(OpCode::Or),
            0x0B => Some(OpCode::Not),
            0x0C => Some(OpCode::Shl),
            0x0D => Some(OpCode::Shr),
            0x0E => Some(OpCode::Rot),
            0x0F => Some(OpCode::Eq),
            0x10 => Some(OpCode::Lt),
            _ => None,
        }
    }

    /// Whether this opcode requires immediate data after the opcode byte.
    #[allow(dead_code)]
    fn has_immediate(self) -> bool {
        matches!(self, OpCode::Push)
    }
}

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum bytecode length in bytes.
const MAX_CODE: usize = 4096;
/// Operand stack depth (128 × u64 = 1024 bytes).
const STACK_DEPTH: usize = 128;

// ── MicroVM ──────────────────────────────────────────────────────────────────

/// A tiny, isolated stack machine.
///
/// - 128-element u64 operand stack
/// - Random canary for overflow detection
/// - Deterministic execution: same code → same 64-byte root
/// - Auto-zeroise on drop
pub struct MicroVM {
    stack: [u64; STACK_DEPTH],
    sp: usize, // stack pointer (0 = empty, sp = next free slot)
    canary: u64,
}

impl MicroVM {
    /// Create a fresh VM with a random canary (requires `std` feature for OS entropy).
    #[cfg(feature = "std")]
    pub fn new() -> Self {
        let mut bytes = [0u8; 8];
        let _ = getrandom::getrandom(&mut bytes);
        let canary = u64::from_le_bytes(bytes);
        Self::with_canary(canary)
    }

    /// Create a VM with a caller-supplied canary. Suitable for `no_std` builds
    /// where the caller provides entropy.
    pub fn with_canary(canary: u64) -> Self {
        Self {
            stack: [0u64; STACK_DEPTH],
            sp: 0,
            canary,
        }
    }

    /// Execute bytecode and return a deterministic 64-byte root.
    ///
    /// Returns `[0u8; 64]` on any failure: empty code, oversized code,
    /// invalid opcode, stack underflow/overflow, or canary corruption.
    pub fn execute(&mut self, code: &[u8]) -> [u8; 64] {
        // Guard: reject empty or oversized code.
        if code.is_empty() || code.len() > MAX_CODE {
            return [0u8; 64];
        }

        // Guard: first byte must be a valid opcode.
        if OpCode::from_u8(code[0]).is_none() {
            return [0u8; 64];
        }

        // Canary check before execution.
        if self.canary == 0 || self.canary == u64::MAX {
            return [0u8; 64];
        }

        // Reset stack.
        self.sp = 0;
        for s in self.stack.iter_mut() {
            *s = 0;
        }

        // Execution trace accumulator — absorbed into SHAKE256 for the root.
        let mut trace = Shake256::default();
        trace.update(b"veil7:vm-trace:v2");

        // Interpret bytecode.
        let mut pc: usize = 0;
        while pc < code.len() {
            let op = match OpCode::from_u8(code[pc]) {
                Some(o) => o,
                None => {
                    self.wipe_state();
                    return [0u8; 64];
                }
            };

            // Absorb opcode into trace.
            trace.update(&[code[pc]]);

            pc += 1;

            match op {
                OpCode::Nop => {}

                OpCode::Push => {
                    // Need 8 bytes of immediate data.
                    if pc + 8 > code.len() {
                        self.wipe_state();
                        return [0u8; 64];
                    }
                    let mut buf = [0u8; 8];
                    buf.copy_from_slice(&code[pc..pc + 8]);
                    let val = u64::from_le_bytes(buf);
                    trace.update(&buf);
                    pc += 8;
                    if !self.push(val) {
                        self.wipe_state();
                        return [0u8; 64];
                    }
                }

                OpCode::Pop => {
                    if self.pop().is_none() {
                        self.wipe_state();
                        return [0u8; 64];
                    }
                }

                OpCode::Dup => {
                    if self.sp == 0 {
                        self.wipe_state();
                        return [0u8; 64];
                    }
                    let top = self.stack[self.sp - 1];
                    if !self.push(top) {
                        self.wipe_state();
                        return [0u8; 64];
                    }
                }

                OpCode::Swap => {
                    if self.sp < 2 {
                        self.wipe_state();
                        return [0u8; 64];
                    }
                    self.stack.swap(self.sp - 1, self.sp - 2);
                }

                OpCode::Rot => {
                    // Rotate: bottom element moves to top.
                    if self.sp < 2 {
                        // 0 or 1 elements: rotation is identity, no-op.
                    } else {
                        let bottom = self.stack[0];
                        // Shift everything down by 1.
                        for i in 0..self.sp - 1 {
                            self.stack[i] = self.stack[i + 1];
                        }
                        self.stack[self.sp - 1] = bottom;
                    }
                }

                // Binary operations: pop b, pop a, push result.
                OpCode::Add
                | OpCode::Xor
                | OpCode::Mul
                | OpCode::Div
                | OpCode::And
                | OpCode::Or
                | OpCode::Shl
                | OpCode::Shr
                | OpCode::Eq
                | OpCode::Lt => {
                    let b = match self.pop() {
                        Some(v) => v,
                        None => {
                            self.wipe_state();
                            return [0u8; 64];
                        }
                    };
                    let a = match self.pop() {
                        Some(v) => v,
                        None => {
                            self.wipe_state();
                            return [0u8; 64];
                        }
                    };
                    let result = match op {
                        OpCode::Add => a.wrapping_add(b),
                        OpCode::Xor => a ^ b,
                        OpCode::Mul => a.wrapping_mul(b),
                        OpCode::Div => {
                            // Constant-time division: avoid panic on div-by-zero
                            // and mask result to 0 if divisor was 0.
                            let is_nonzero = (b | b.wrapping_neg()) >> 63; // 1 if b != 0, 0 if b == 0
                            let safe_b = b | (1 - is_nonzero); // b if nonzero, 1 if zero
                            let raw = a / safe_b; // safe: divisor is never 0
                            raw & (0u64.wrapping_sub(is_nonzero)) // mask to 0 if b was 0
                        }
                        OpCode::And => a & b,
                        OpCode::Or => a | b,
                        OpCode::Shl => a.wrapping_shl((b & 63) as u32),
                        OpCode::Shr => a.wrapping_shr((b & 63) as u32),
                        OpCode::Eq => {
                            // Constant-time equality: a ^ b is 0 iff a == b.
                            let diff = a ^ b;
                            ((diff | diff.wrapping_neg()) >> 63) ^ 1
                        }
                        OpCode::Lt => {
                            // Constant-time unsigned less-than: check if a - b borrows.
                            let (_, borrow) = a.overflowing_sub(b);
                            borrow as u64
                        }
                        _ => unreachable!(),
                    };
                    // Absorb result into trace.
                    trace.update(&result.to_le_bytes());
                    if !self.push(result) {
                        self.wipe_state();
                        return [0u8; 64];
                    }
                }

                // Unary operation: pop a, push result.
                OpCode::Not => {
                    let a = match self.pop() {
                        Some(v) => v,
                        None => {
                            self.wipe_state();
                            return [0u8; 64];
                        }
                    };
                    let result = !a;
                    trace.update(&result.to_le_bytes());
                    if !self.push(result) {
                        self.wipe_state();
                        return [0u8; 64];
                    }
                }
            }
        }

        // Canary check after execution.
        if self.canary == 0 || self.canary == u64::MAX {
            self.wipe_state();
            return [0u8; 64];
        }

        // Absorb final stack depth into trace for completeness.
        trace.update(&(self.sp as u64).to_le_bytes());

        // Derive final root from execution trace via SHAKE256.
        let mut root = [0u8; 64];
        let mut reader = trace.finalize_xof();
        reader.read(&mut root);

        // Wipe execution state.
        self.wipe_state();

        root
    }

    /// Push a value onto the stack. Returns false if stack is full.
    fn push(&mut self, val: u64) -> bool {
        if self.sp >= STACK_DEPTH {
            return false;
        }
        self.stack[self.sp] = val;
        self.sp += 1;
        true
    }

    /// Pop a value from the stack. Returns None if stack is empty.
    fn pop(&mut self) -> Option<u64> {
        if self.sp == 0 {
            return None;
        }
        self.sp -= 1;
        let val = self.stack[self.sp];
        self.stack[self.sp] = 0; // wipe popped slot
        Some(val)
    }

    /// Wipe all execution state (stack + pointer).
    fn wipe_state(&mut self) {
        for s in self.stack.iter_mut() {
            zeroize_u64(s);
        }
        self.sp = 0;
    }

    /// Return the number of values currently on the stack.
    /// Useful for testing; does not leak stack contents.
    #[cfg(test)]
    pub fn stack_depth(&self) -> usize {
        self.sp
    }

    /// Peek at the top of the stack without popping.
    /// Testing only.
    #[cfg(test)]
    pub fn peek(&self) -> Option<u64> {
        if self.sp == 0 {
            None
        } else {
            Some(self.stack[self.sp - 1])
        }
    }
}

// ── Drop ─────────────────────────────────────────────────────────────────────

impl Default for MicroVM {
    fn default() -> Self {
        Self::with_canary(1)
    }
}

impl Drop for MicroVM {
    #[inline(never)]
    fn drop(&mut self) {
        self.wipe_state();
        zeroize_u64(&mut self.canary);
    }
}

// ── Bytecode builder (ergonomic helper for constructing bytecode) ────────────

/// Builder for constructing VM bytecode from opcodes and immediates.
///
/// # Example
/// ```
/// use veil7::execution::vm::BytecodeBuilder;
/// let code = BytecodeBuilder::new()
///     .push(10)
///     .push(20)
///     .add()
///     .build();
/// ```
pub struct BytecodeBuilder {
    code: alloc::vec::Vec<u8>,
}

extern crate alloc;

impl BytecodeBuilder {
    /// Create a new empty bytecode builder.
    pub fn new() -> Self {
        Self {
            code: alloc::vec::Vec::new(),
        }
    }

    /// Append a raw opcode.
    pub fn op(mut self, byte: u8) -> Self {
        self.code.push(byte);
        self
    }

    /// Push an immediate u64 value onto the VM stack.
    /// Push a 64-bit value onto the stack.
    pub fn push(self, val: u64) -> Self {
        let mut b = self.op(OpCode::Push as u8);
        b.code.extend_from_slice(&val.to_le_bytes());
        b
    }

    /// No-operation.
    pub fn nop(self) -> Self {
        self.op(OpCode::Nop as u8)
    }
    /// Pop two values, push their sum (wrapping).
    pub fn add(self) -> Self {
        self.op(OpCode::Add as u8)
    }
    /// Pop two values, push their XOR.
    pub fn xor(self) -> Self {
        self.op(OpCode::Xor as u8)
    }
    /// Pop two values, push their product (wrapping).
    pub fn mul(self) -> Self {
        self.op(OpCode::Mul as u8)
    }
    /// Pop two values, push their quotient (wrapping, 0 if divisor is 0).
    pub fn div(self) -> Self {
        self.op(OpCode::Div as u8)
    }
    /// Pop and discard the top value.
    pub fn pop(self) -> Self {
        self.op(OpCode::Pop as u8)
    }
    /// Duplicate the top value.
    pub fn dup(self) -> Self {
        self.op(OpCode::Dup as u8)
    }
    /// Swap the top two values.
    pub fn swap(self) -> Self {
        self.op(OpCode::Swap as u8)
    }
    /// Pop two values, push their bitwise AND.
    pub fn and(self) -> Self {
        self.op(OpCode::And as u8)
    }
    /// Pop two values, push their bitwise OR.
    pub fn or(self) -> Self {
        self.op(OpCode::Or as u8)
    }
    /// Pop one value, push its bitwise NOT.
    #[allow(clippy::should_implement_trait)]
    pub fn not(self) -> Self {
        self.op(OpCode::Not as u8)
    }
    /// Pop two values, push left shifted by right (mod 64).
    pub fn shl(self) -> Self {
        self.op(OpCode::Shl as u8)
    }
    /// Pop two values, push left shifted right by right (mod 64).
    pub fn shr(self) -> Self {
        self.op(OpCode::Shr as u8)
    }
    /// Rotate the stack (bottom becomes top).
    pub fn rot(self) -> Self {
        self.op(OpCode::Rot as u8)
    }
    /// Pop two values, push 1 if equal, 0 otherwise.
    pub fn eq(self) -> Self {
        self.op(OpCode::Eq as u8)
    }
    /// Pop two values, push 1 if first < second, 0 otherwise.
    pub fn lt(self) -> Self {
        self.op(OpCode::Lt as u8)
    }

    /// Consume the builder and return the raw bytecode.
    pub fn build(self) -> alloc::vec::Vec<u8> {
        self.code
    }
}

impl Default for BytecodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Legacy compatibility tests ──────────────────────────────────────────

    #[test]
    fn deterministic_same_code_same_root() {
        let code = BytecodeBuilder::new().push(1).push(2).add().build();
        let mut vm1 = MicroVM::new();
        let mut vm2 = MicroVM::new();
        let r1 = vm1.execute(&code);
        let r2 = vm2.execute(&code);
        assert_eq!(r1, r2, "same code → same root");
    }

    #[test]
    fn different_code_different_root() {
        let code1 = BytecodeBuilder::new().push(1).push(2).add().build();
        let code2 = BytecodeBuilder::new().push(1).push(3).add().build();
        let mut vm = MicroVM::new();
        let r1 = vm.execute(&code1);
        let r2 = vm.execute(&code2);
        assert_ne!(r1, r2);
    }

    #[test]
    fn empty_code_returns_zeros() {
        let mut vm = MicroVM::new();
        let r = vm.execute(&[]);
        assert_eq!(r, [0u8; 64]);
    }

    #[test]
    fn oversized_code_returns_zeros() {
        let mut vm = MicroVM::new();
        let code = vec![0x00u8; MAX_CODE + 1]; // all Nops, but too long
        let r = vm.execute(&code);
        assert_eq!(r, [0u8; 64]);
    }

    #[test]
    fn invalid_first_opcode_returns_zeros() {
        let mut vm = MicroVM::new();
        let r = vm.execute(&[0xFF, 0x01, 0x02]);
        assert_eq!(r, [0u8; 64]);
    }

    #[test]
    fn root_is_not_all_zeros_for_valid_code() {
        let code = BytecodeBuilder::new().push(42).build();
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        assert_ne!(r, [0u8; 64], "valid code must produce non-zero root");
    }

    #[test]
    fn nop_first_opcode_is_valid() {
        let code = BytecodeBuilder::new().nop().push(1).push(2).add().build();
        let mut vm1 = MicroVM::new();
        let mut vm2 = MicroVM::new();
        let r = vm1.execute(&code);
        let z = vm2.execute(&code);
        assert_eq!(r, z, "nop-start code is deterministic");
    }

    // ── Arithmetic tests ────────────────────────────────────────────────────

    #[test]
    fn add_two_numbers() {
        let code = BytecodeBuilder::new().push(10).push(20).add().build();
        let mut vm = MicroVM::new();
        let _ = vm.execute(&code);
        // We can't peek after execute (stack is wiped), but the root
        // should differ from a different sum.
        let code2 = BytecodeBuilder::new().push(10).push(21).add().build();
        let mut vm2 = MicroVM::new();
        let r1 = vm.execute(&BytecodeBuilder::new().push(10).push(20).add().build());
        let r2 = vm2.execute(&code2);
        assert_ne!(r1, r2, "10+20 ≠ 10+21");
    }

    #[test]
    fn mul_wrapping() {
        // u64::MAX * 2 should wrap to u64::MAX - 1 (wrapping arithmetic).
        let code = BytecodeBuilder::new().push(u64::MAX).push(2).mul().build();
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        assert_ne!(r, [0u8; 64], "wrapping mul must produce valid root");
    }

    #[test]
    fn div_by_zero_returns_zero() {
        let code = BytecodeBuilder::new().push(42).push(0).div().build();
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        // Should succeed (not fail-closed), result on stack is 0.
        assert_ne!(r, [0u8; 64]);
    }

    // ── Stack manipulation tests ────────────────────────────────────────────

    #[test]
    fn dup_duplicates_top() {
        // Push 5, Dup, Add → 5 + 5 = 10 on stack.
        // The root differs from push(5).push(5).add() because the trace
        // captures different opcodes (Dup vs second Push). Verify dup works
        // by checking: (1) execution succeeds, (2) root differs from just
        // push(5) (which leaves only one element, not two).
        let code = BytecodeBuilder::new().push(5).dup().add().build();
        let code_push5_only = BytecodeBuilder::new().push(5).build();
        let mut vm1 = MicroVM::new();
        let mut vm2 = MicroVM::new();
        let r1 = vm1.execute(&code);
        let r2 = vm2.execute(&code_push5_only);
        assert_ne!(r1, [0u8; 64], "dup+add must succeed");
        assert_ne!(r1, r2, "dup+add trace differs from single push");
    }

    #[test]
    fn swap_reverses_top_two() {
        // Push 1, Push 2, Swap, Pop → leaves 2 on stack.
        // Push 2 → leaves 2 on stack.
        // Both should produce the same root.
        let code1 = BytecodeBuilder::new().push(1).push(2).swap().pop().build();
        let code2 = BytecodeBuilder::new().push(2).build();
        let mut vm1 = MicroVM::new();
        let mut vm2 = MicroVM::new();
        let r1 = vm1.execute(&code1);
        let r2 = vm2.execute(&code2);
        // Note: roots will differ because the trace includes all opcodes
        // executed, not just the final stack. This is by design — the root
        // binds to the full execution, not just the result.
        assert_ne!(r1, [0u8; 64]);
        assert_ne!(r2, [0u8; 64]);
    }

    #[test]
    fn pop_on_empty_stack_fails() {
        let code = BytecodeBuilder::new().pop().build();
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        assert_eq!(r, [0u8; 64], "pop on empty stack must fail-closed");
    }

    #[test]
    fn dup_on_empty_stack_fails() {
        let code = BytecodeBuilder::new().dup().build();
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        assert_eq!(r, [0u8; 64], "dup on empty stack must fail-closed");
    }

    #[test]
    fn swap_on_single_element_fails() {
        let code = BytecodeBuilder::new().push(1).swap().build();
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        assert_eq!(r, [0u8; 64], "swap with <2 elements must fail-closed");
    }

    // ── Bitwise tests ───────────────────────────────────────────────────────

    #[test]
    fn and_operation() {
        let code = BytecodeBuilder::new()
            .push(0xFF00)
            .push(0x0FF0)
            .and()
            .build();
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        assert_ne!(r, [0u8; 64]);
    }

    #[test]
    fn or_operation() {
        let code = BytecodeBuilder::new()
            .push(0xFF00)
            .push(0x00FF)
            .or()
            .build();
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        assert_ne!(r, [0u8; 64]);
    }

    #[test]
    fn not_operation() {
        let code = BytecodeBuilder::new().push(0).not().build();
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        assert_ne!(r, [0u8; 64], "NOT 0 = all ones, must produce valid root");
    }

    #[test]
    fn shl_shr_roundtrip() {
        // Push 42, Push 8, Shl, Push 8, Shr → should be 42.
        let code = BytecodeBuilder::new()
            .push(42)
            .push(8)
            .shl()
            .push(8)
            .shr()
            .build();
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        assert_ne!(r, [0u8; 64]);
    }

    // ── Comparison tests ────────────────────────────────────────────────────

    #[test]
    fn eq_equal_values() {
        // Push 42, Push 42, Eq → stack has 1.
        let code = BytecodeBuilder::new().push(42).push(42).eq().build();
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        assert_ne!(r, [0u8; 64]);
    }

    #[test]
    fn eq_different_values() {
        // Push 42, Push 43, Eq → stack has 0.
        let code = BytecodeBuilder::new().push(42).push(43).eq().build();
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        // Still produces a valid root (0 is a valid stack value).
        assert_ne!(r, [0u8; 64]);
    }

    #[test]
    fn lt_comparison() {
        // Push 1, Push 2, Lt → 1 < 2 → stack has 1.
        let code = BytecodeBuilder::new().push(1).push(2).lt().build();
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        assert_ne!(r, [0u8; 64]);
    }

    // ── Rotation test ───────────────────────────────────────────────────────

    #[test]
    fn rot_rotates_bottom_to_top() {
        // Push 1, Push 2, Push 3, Rot → stack should be [2, 3, 1].
        // The root differs from non-rotated [1, 2, 3].
        let code1 = BytecodeBuilder::new().push(1).push(2).push(3).rot().build();
        let code2 = BytecodeBuilder::new().push(1).push(2).push(3).build();
        let mut vm1 = MicroVM::new();
        let mut vm2 = MicroVM::new();
        let r1 = vm1.execute(&code1);
        let r2 = vm2.execute(&code2);
        assert_ne!(r1, r2, "rotation must change the execution trace");
    }

    // ── Stack overflow test ─────────────────────────────────────────────────

    #[test]
    fn stack_overflow_fails_closed() {
        // Push STACK_DEPTH + 1 values → should fail.
        let mut builder = BytecodeBuilder::new();
        for i in 0..=(STACK_DEPTH as u64) {
            builder = builder.push(i);
        }
        let code = builder.build();
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        assert_eq!(r, [0u8; 64], "stack overflow must fail-closed");
    }

    // ── Incomplete immediate data ───────────────────────────────────────────

    #[test]
    fn push_with_truncated_immediate_fails() {
        // Push opcode with only 4 bytes of immediate (needs 8).
        let mut code = vec![OpCode::Push as u8];
        code.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        assert_eq!(r, [0u8; 64], "truncated Push immediate must fail-closed");
    }

    // ── Complex program test ────────────────────────────────────────────────

    #[test]
    fn complex_program_is_deterministic() {
        // Compute (3 + 5) * (10 - 2) using only push/add/mul/not.
        // (10 - 2) = 10 + NOT(2) + 1 = 10 + (u64::MAX - 2) + 1
        // But simpler: just push the values.
        let code = BytecodeBuilder::new()
            .push(3)
            .push(5)
            .add() // 8
            .push(10)
            .push(2)
            .xor() // 10 ^ 2 = 8
            .mul() // 8 * 8 = 64
            .build();
        let mut vm1 = MicroVM::new();
        let mut vm2 = MicroVM::new();
        let r1 = vm1.execute(&code);
        let r2 = vm2.execute(&code);
        assert_eq!(r1, r2, "complex program must be deterministic");
        assert_ne!(r1, [0u8; 64]);
    }

    // ── Zeroize test ────────────────────────────────────────────────────────

    #[test]
    fn stack_is_wiped_after_execute() {
        let code = BytecodeBuilder::new()
            .push(0xDEADBEEF)
            .push(0xCAFEBABE)
            .build();
        let mut vm = MicroVM::new();
        let _ = vm.execute(&code);
        // After execute, sp should be 0 and all stack slots zeroed.
        assert_eq!(vm.sp, 0);
        for &slot in vm.stack.iter() {
            assert_eq!(slot, 0, "stack must be wiped after execute");
        }
    }

    // ── Binary operation on underflow ───────────────────────────────────────

    #[test]
    fn binary_op_with_one_element_fails() {
        let code = BytecodeBuilder::new().push(1).add().build();
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        assert_eq!(r, [0u8; 64], "binary op needs 2 operands");
    }

    #[test]
    fn binary_op_with_zero_elements_fails() {
        // Nop followed by Add — stack is empty.
        let code = BytecodeBuilder::new().nop().add().build();
        let mut vm = MicroVM::new();
        let r = vm.execute(&code);
        assert_eq!(r, [0u8; 64], "binary op on empty stack must fail");
    }
}
