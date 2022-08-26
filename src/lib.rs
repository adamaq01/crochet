//! [![github]](https://github.com/Adamaq01/crochet)&ensp;[![crates-io]](https://crates.io/crates/crochet)&ensp;[![docs-rs]](crate)
//!
//! [github]: https://img.shields.io/badge/github-8da0cb?style=for-the-badge&labelColor=555555&logo=github
//! [crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
//! [docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
//!
//! <br>
//!
//! Crochet is a library for hooking dynamic libraries with convenient macros.
//! It can also enforce the availability of the libraries and symbols at compile time.
//!
//! <br>
//!
//! It is basically [skyline-rs](https://github.com/ultimate-research/skyline-rs) macros but for x86/x64.
//! It uses [detour](https://github.com/lostinspiration/detour-rs) to hook functions and [dlopen2](https://github.com/OpenByteDev/dlopen2) to load libraries.
//!
//! # Example
//!
//! ```rust
//! use winapi::ctypes::c_int;
//! use winapi::shared::minwindef::{BOOL, DWORD, HINSTANCE, LPVOID, TRUE, UINT};
//! use winapi::shared::windef::HWND;
//! use winapi::um::winnt::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH, LPCWSTR};
//!
//! #[no_mangle]
//! #[allow(non_snake_case, unused_variables)]
//! extern "system" fn DllMain(dll_module: HINSTANCE, call_reason: DWORD, reserved: LPVOID) -> BOOL {
//!     match call_reason {
//!         DLL_PROCESS_ATTACH => {
//!             crochet::enable!(messageboxw_hook).expect("Could not enable messageboxw hook")
//!         }
//!         DLL_PROCESS_DETACH => {
//!             crochet::disable!(messageboxw_hook).expect("Could not disable messageboxw hook")
//!         }
//!         _ => {}
//!     }
//!
//!     TRUE
//! }
//!
//! #[crochet::hook(compile_check, "user32.dll", "MessageBoxW")]
//! fn messageboxw_hook(hwnd: HWND, _text: LPCWSTR, caption: LPCWSTR, u_type: UINT) -> c_int {
//!     let text = "Tu as fait mouche, Mouche !\0"
//!         .encode_utf16()
//!         .collect::<Vec<u16>>();
//!
//!     call_original!(hwnd, text.as_ptr(), caption, u_type)
//! }
//! ```

pub use crochet_macro::*;
pub use lazy_static;
pub use dlopen2;
pub use detour;
