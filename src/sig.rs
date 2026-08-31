//! IDA-style byte-pattern matching, shared by the Linux and Windows backends.
//!
//! Everything this tool touches in the game is located by pattern, never by a
//! hard-coded address or vtable slot index. That is not stylistic: the
//! 2026-08-24 CS:S update moved code ~0x1e80, moved vtables ~0xa90, and gave
//! launcher.so's data segment an extra page. A stale code address merely fails
//! a byte check, but a stale *vtable slot* address still points at a valid
//! function pointer belonging to a different class, so a hook installs
//! "successfully" and corrupts an unrelated virtual. Patterns describe what the
//! code *is*, so they survive relayout; when one genuinely stops matching, the
//! feature disables itself instead of writing somewhere wrong.

// This module is compiled into both crates (the patcher binary and the
// LD_PRELOAD library) and into both platform backends, each of which uses a
// different subset of it, so per-crate dead-code warnings here are noise.
#![allow(dead_code)]

/// A byte pattern with wildcards, written the way every disassembler prints it:
/// `"F3 0F 58 ?? 74 12 00 00"`. `??` (or `?`) matches any byte.
#[derive(Clone, Debug, PartialEq)]
pub struct Pattern(Vec<Option<u8>>);

impl Pattern {
    /// Parse a pattern spec. Returns None if it is malformed or empty, so a
    /// typo in a literal fails at the call site instead of silently matching
    /// nothing.
    pub fn parse(spec: &str) -> Option<Pattern> {
        let mut out = Vec::new();
        for tok in spec.split_whitespace() {
            match tok {
                "?" | "??" => out.push(None),
                hex if hex.len() == 2 => out.push(Some(u8::from_str_radix(hex, 16).ok()?)),
                _ => return None,
            }
        }
        (!out.is_empty()).then_some(Pattern(out))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Byte index of each wildcard, in order. Used to pull a struct offset out
    /// of a matched instruction's displacement field.
    pub fn wildcards(&self) -> impl Iterator<Item = usize> + '_ {
        self.0
            .iter()
            .enumerate()
            .filter_map(|(i, b)| b.is_none().then_some(i))
    }

    pub fn matches_at(&self, hay: &[u8], at: usize) -> bool {
        hay.len() >= at + self.0.len()
            && self
                .0
                .iter()
                .zip(&hay[at..])
                .all(|(p, &got)| p.is_none_or(|want| want == got))
    }

    pub fn find_from(&self, hay: &[u8], from: usize) -> Option<usize> {
        let last = hay.len().checked_sub(self.0.len())?;
        (from..=last).find(|&i| self.matches_at(hay, i))
    }

    pub fn find(&self, hay: &[u8]) -> Option<usize> {
        self.find_from(hay, 0)
    }

    pub fn find_all(&self, hay: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        let mut at = 0;
        while let Some(i) = self.find_from(hay, at) {
            out.push(i);
            at = i + 1;
        }
        out
    }
}

/// A patchable code signature: locate `pat`, then rewrite `len` bytes at
/// `at` bytes into the match.
///
/// Both platform backends carry their own table of these — the byte encodings
/// differ per compiler and per architecture, but the located instruction and
/// the edit are the same idea everywhere.
pub struct Sig {
    /// Human name, printed in status output.
    pub name: &'static str,
    /// IDA-style pattern for `Pattern::parse`.
    pub pat: &'static str,
    /// Offset into the match of the bytes to rewrite.
    pub at: usize,
    /// How many bytes to rewrite.
    pub len: usize,
}

impl Sig {
    /// Parse the pattern, or None if the literal is malformed.
    pub fn pattern(&self) -> Option<Pattern> {
        let p = Pattern::parse(self.pat)?;
        // a signature whose patch window falls outside its own match is a typo
        (self.at + self.len <= p.len()).then_some(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_and_wildcards() {
        let p = Pattern::parse("F3 0F 58 ?? 74 ?").unwrap();
        assert_eq!(p.len(), 6);
        assert_eq!(p.wildcards().collect::<Vec<_>>(), vec![3, 5]);
    }

    #[test]
    fn rejects_malformed_specs() {
        for bad in ["", "   ", "F", "FFF", "ZZ", "F3 0F 5"] {
            assert!(Pattern::parse(bad).is_none(), "accepted {bad:?}");
        }
    }

    #[test]
    fn wildcards_match_any_byte_but_length_is_exact() {
        let p = Pattern::parse("AA ?? CC").unwrap();
        assert!(p.matches_at(&[0xAA, 0x00, 0xCC], 0));
        assert!(p.matches_at(&[0xAA, 0xFF, 0xCC], 0));
        assert!(!p.matches_at(&[0xAA, 0xFF, 0xCD], 0));
        assert!(
            !p.matches_at(&[0xAA, 0xFF], 0),
            "must not match past the end"
        );
    }

    #[test]
    fn finds_every_occurrence() {
        let hay = [0x90, 0xAA, 0x01, 0xCC, 0x90, 0xAA, 0x02, 0xCC];
        let p = Pattern::parse("AA ?? CC").unwrap();
        assert_eq!(p.find_all(&hay), vec![1, 5]);
        assert_eq!(p.find(&hay), Some(1));
    }

    #[test]
    fn rejects_a_signature_whose_patch_window_escapes_its_match() {
        // 4-byte pattern, but the table claims to rewrite 6 bytes at +2
        let bad = Sig {
            name: "bad",
            pat: "AA BB CC DD",
            at: 2,
            len: 6,
        };
        assert!(bad.pattern().is_none());
        let ok = Sig {
            name: "ok",
            pat: "AA BB CC DD",
            at: 2,
            len: 2,
        };
        assert!(ok.pattern().is_some());
    }

    #[test]
    fn pulls_a_displacement_out_of_a_match() {
        // movdqu 0x38(%rbx),%xmm2  ->  F3 0F 6F 53 38 ; disp8 at index 4
        let hay = [0xF3, 0x0F, 0x6F, 0x53, 0x38];
        let p = Pattern::parse("F3 0F 6F 53 ??").unwrap();
        let at = p.find(&hay).unwrap();
        let disp = p.wildcards().next().unwrap();
        assert_eq!(hay[at + disp], 0x38);
    }
}
