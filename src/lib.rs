use quote::{ToTokens, quote};
use proc_macro::TokenStream;
use convert_case::{Case, Casing};
use syn::{parse_quote, parse_macro_input, token, Ident, AttrStyle, Stmt, LitStr, Token, parse::Parse, ExprPath};
use proc_macro2::{Span, TokenStream as TokenStream2};

struct HookAttrs {
    module: LitStr,
    symbol: LitStr,
}

impl Parse for HookAttrs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let module = input.parse()?;
        input.parse::<Token![,]>()?;
        let symbol = input.parse()?;
        Ok(HookAttrs { module, symbol })
    }
}

fn remove_mut(arg: &syn::FnArg) -> syn::FnArg {
    let mut arg = arg.clone();

    if let syn::FnArg::Typed(ref mut arg) = arg {
        if let syn::Pat::Ident(ref mut arg) = *arg.pat {
            arg.by_ref = None;
            arg.mutability = None;
            arg.subpat = None;
        }
    }

    arg
}

#[proc_macro_attribute]
pub fn hook(attrs: TokenStream, input: TokenStream) -> TokenStream {
    let mut mod_fn = parse_macro_input!(input as syn::ItemFn);
    let attrs = parse_macro_input!(attrs as HookAttrs);

    // #[no_mangle]
    mod_fn.attrs.push(
        syn::Attribute {
            pound_token: token::Pound { spans: [Span::call_site()] },
            style: AttrStyle::Outer,
            bracket_token: token::Bracket { span: Span::call_site() },
            path: Ident::new("no_mangle", Span::call_site()).into(),
            tokens: TokenStream2::new(),
        }
    );

    // extern "C"
    mod_fn.sig.abi = Some(syn::Abi {
        extern_token: syn::token::Extern { span: Span::call_site() },
        name: Some(syn::LitStr::new("C", Span::call_site())),
    });

    let args_tokens = mod_fn.sig.inputs.iter().map(remove_mut);
    let return_tokens = mod_fn.sig.output.to_token_stream();

    let _const = Ident::new(format!("_{}", mod_fn.sig.ident.to_string().to_case(Case::UpperSnake)).as_str(), Span::call_site());

    let module = attrs.module;
    let symbol = attrs.symbol;

    let ident = mod_fn.sig.ident.clone();

    let orig_stmt: Stmt = parse_quote! {
        #[allow(unused_macros)]
        macro_rules! original {
            () => {
                unsafe {
                    ::core::mem::transmute::<_, extern "C" fn(#(#args_tokens),*) #return_tokens>(
                        #_const.trampoline()
                    )
                }
            }
        }
    };
    mod_fn.block.stmts.insert(0, orig_stmt);
    let orig_stmt: Stmt = parse_quote! {
            #[allow(unused_macros)]
            macro_rules! call_original {
                ($($args:expr),* $(,)?) => {
                    original!()($($args),*)
                }
            }
        };
    mod_fn.block.stmts.insert(1, orig_stmt);

    let hook_enable = quote::format_ident!("{}_enable", ident);
    let hook_disable = quote::format_ident!("{}_disable", ident);
    let hook_is_enabled = quote::format_ident!("{}_is_enabled", ident);

    quote!(
        ::lazy_static::lazy_static! {
            static ref #_const: ::detour::RawDetour = unsafe {
                let module = match ::winapi::um::libloaderapi::GetModuleHandleW(#module
                    .encode_utf16()
                    .chain(std::iter::once(0))
                    .collect::<Vec<u16>>().as_ptr()) as usize {
                        0 => Err(::std::io::Error::last_os_error().to_string()),
                        handle => Ok(handle as ::winapi::shared::minwindef::HMODULE),
                    }.expect("Could not find module");
                let symbol = ::std::ffi::CString::new(#symbol).map_err(|err| err.to_string())
                    .and_then(|name| unsafe {
                        match ::winapi::um::libloaderapi::GetProcAddress(module, name.as_ptr()) as usize {
                            0 => Err(::std::io::Error::last_os_error().to_string()),
                            address => Ok(address),
                        }
                    }).expect("Could not find symbol in module");

                ::detour::RawDetour::new(symbol as *const (), #ident as *const ()).expect("Could not load detour")
            };
        }

        #mod_fn

        pub fn #hook_enable() -> ::detour::Result<()> {
            unsafe { #_const.enable() }
        }

        pub fn #hook_disable() -> ::detour::Result<()> {
            unsafe { #_const.disable() }
        }

        pub fn #hook_is_enabled() -> bool {
            #_const.is_enabled()
        }
    ).into()
}

#[proc_macro]
pub fn enable(attrs: TokenStream) -> TokenStream {
    let mut hook = parse_macro_input!(attrs as ExprPath);

    let last_seg = hook.path.segments.iter_mut().last().unwrap();

    last_seg.ident = quote::format_ident!("{}_enable", last_seg.ident);
    quote!(
        #hook()
    ).into()
}

#[proc_macro]
pub fn disable(attrs: TokenStream) -> TokenStream {
    let mut hook = parse_macro_input!(attrs as ExprPath);

    let last_seg = hook.path.segments.iter_mut().last().unwrap();

    last_seg.ident = quote::format_ident!("{}_disable", last_seg.ident);
    quote!(
        #hook()
    ).into()
}

#[proc_macro]
pub fn is_enabled(attrs: TokenStream) -> TokenStream {
    let mut hook = parse_macro_input!(attrs as syn::ExprPath);

    let last_seg = hook.path.segments.iter_mut().last().unwrap();

    last_seg.ident = quote::format_ident!("{}_is_enabled", last_seg.ident);
    quote!(
        #hook()
    ).into()
}
