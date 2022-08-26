use convert_case::{Case, Casing};
use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{quote, ToTokens};
use syn::{
    parse::Parse, parse_macro_input, parse_quote, token, AttrStyle, ExprPath, Ident, LitBool,
    LitStr, Stmt, Token,
};

mod kw {
    syn::custom_keyword!(library);
    syn::custom_keyword!(symbol);
    syn::custom_keyword!(compile_check);
}

struct HookAttrs {
    library: LitStr,
    symbol: LitStr,
    compile_check: bool,
}

impl Parse for HookAttrs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut library = None;
        let mut symbol = None;
        let mut unknown = None;
        let mut compile_check = false;
        while !input.is_empty() {
            let look = input.lookahead1();
            if look.peek(kw::library) {
                input.parse::<kw::library>()?;
                input.parse::<Token![=]>()?;
                library = Some(input.parse::<LitStr>()?);
                if symbol.is_none() && unknown.is_some() {
                    symbol = unknown;
                    unknown = None;
                }
            } else if look.peek(kw::symbol) {
                input.parse::<kw::symbol>()?;
                input.parse::<Token![=]>()?;
                symbol = Some(input.parse::<LitStr>()?);
                if library.is_none() && unknown.is_some() {
                    library = unknown;
                    unknown = None;
                }
            } else if look.peek(kw::compile_check) {
                input.parse::<kw::compile_check>()?;
                let look = input.lookahead1();
                if look.peek(Token![=]) {
                    input.parse::<Token![=]>()?;
                    compile_check = input.parse::<LitBool>()?.value;
                } else {
                    compile_check = true;
                }
            } else if look.peek(LitBool) {
                compile_check = input.parse::<LitBool>()?.value;
            } else if library.is_none() && symbol.is_none() && unknown.is_none() {
                unknown = Some(input.parse::<LitStr>()?);
            } else if symbol.is_none() {
                symbol = Some(input.parse::<LitStr>()?);
            } else if library.is_none() {
                library = Some(input.parse::<LitStr>()?);
            } else {
                return Err(look.error());
            };
            if input.is_empty() {
                break;
            }
            input.parse::<Token![,]>()?;
        }

        if let Some(unknown) = unknown {
            if library.is_none() && symbol.is_none() {
                library = Some(unknown);
            } else if library.is_some() {
                symbol = Some(unknown);
            } else if symbol.is_some() {
                library = Some(unknown);
            } else {
                return Err(syn::Error::new(unknown.span(), "Unknown attribute"));
            }
        }

        if let (Some(library), Some(symbol)) = (library.clone(), symbol.clone()) {
            Ok(HookAttrs {
                library,
                symbol,
                compile_check,
            })
        } else if library.is_some() {
            Err(syn::Error::new(Span::call_site(), "Missing symbol"))
        } else if symbol.is_some() {
            Err(syn::Error::new(Span::call_site(), "Missing library"))
        } else {
            Err(syn::Error::new(
                Span::call_site(),
                "Missing library and symbol",
            ))
        }
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

/// Hooks a function in a dynamic library with the body of the attached function.
///
/// # Example
///
/// ```rust
/// #[crochet::hook("library.so", "a_function", compile_check)]
/// fn simple_hook() {
///     println!("Hooked!");
///     call_original!();
/// }
/// ```
///
/// # Attributes
///
/// - `library`: the name of the dynamic library to hook.
/// - `symbol`: the name of the function to hook.
/// - `compile_check`: whether to check if the library and symbol are available at compile time.
///
/// The macro attributes syntax is very flexible, hence:
/// * the `compile_check` attribute is optional and a boolean value can be specified if wanted.
/// * the `library` attribute is mandatory, though the keyword `library` is optional.
/// * the `symbol` attribute is mandatory, though the keyword `symbol` is optional.
/// * if no prefix are given for the `library` and/or `symbol` attributes, then the first one will be considered as the `library` and the second one as the `symbol`.
///
/// Here are some examples of valid attributes:
/// ```rust
/// #[crochet::hook(library = "library.so", symbol = "a_function", compile_check = true)]
/// // Since no keywords are used, the library must be specified before the symbol.
/// #[crochet::hook("library.so", "a_function", compile_check)]
/// // Since the symbol keyword is used, the library can be specified after.
/// #[crochet::hook(symbol = "a_function", compile_check, "library.so")]
/// // Since the library keyword is used, the symbol can be specified before.
/// #[crochet::hook(compile_check, "a_function", library = "library.so")]
/// ```
///
/// # Panics
///
/// Panics if the dynamic library or the function cannot be found at runtime.
///
/// # See also
///
/// - [`crochet::enable!`](./macro.enable.html)
/// - [`crochet::disable!`](./macro.disable.html)
/// - [`crochet::is_enabled!`](./macro.is_enabled.html)
#[proc_macro_attribute]
pub fn hook(attrs: TokenStream, input: TokenStream) -> TokenStream {
    let mut mod_fn = parse_macro_input!(input as syn::ItemFn);
    let attrs = parse_macro_input!(attrs as HookAttrs);

    // #[no_mangle]
    mod_fn.attrs.push(syn::Attribute {
        pound_token: token::Pound {
            spans: [Span::call_site()],
        },
        style: AttrStyle::Outer,
        bracket_token: token::Bracket {
            span: Span::call_site(),
        },
        path: Ident::new("no_mangle", Span::call_site()).into(),
        tokens: TokenStream2::new(),
    });

    // extern "C"
    mod_fn.sig.abi = Some(syn::Abi {
        extern_token: syn::token::Extern {
            span: Span::call_site(),
        },
        name: Some(LitStr::new("C", Span::call_site())),
    });

    let args_tokens = mod_fn.sig.inputs.iter().map(remove_mut);
    let return_tokens = mod_fn.sig.output.to_token_stream();

    let _const = Ident::new(
        format!(
            "_{}",
            mod_fn.sig.ident.to_string().to_case(Case::UpperSnake)
        )
            .as_str(),
        Span::call_site(),
    );

    let library = attrs.library;
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

    let hook_enable = quote::format_ident!("{}_crochet_enable", ident);
    let hook_disable = quote::format_ident!("{}_crochet_disable", ident);
    let hook_is_enabled = quote::format_ident!("{}_crochet_is_enabled", ident);

    if attrs.compile_check {
        let result: syn::Result<()> = (|| unsafe {
            dlopen2::raw::Library::open(library.value())
                .map_err(|e| syn::Error::new(Span::call_site(), e))?
                .symbol::<*const ()>(symbol.value().as_str())
                .map_err(|e| syn::Error::new(Span::call_site(), e))?;

            Ok(())
        })();
        if let Err(e) = result {
            return e.to_compile_error().into();
        }
    }

    quote!(
        crochet::lazy_static::lazy_static! {
            static ref #_const: crochet::detour::RawDetour = unsafe {
                let symbol = crochet::dlopen2::raw::Library::open(#library)
                    .expect("Could not open library")
                    .symbol::<*const ()>(#symbol)
                    .expect("Could not find symbol in library");

                crochet::detour::RawDetour::new(symbol, #ident as *const ()).expect("Could not load detour")
            };
        }

        #mod_fn

        pub fn #hook_enable() -> crochet::detour::Result<()> {
            unsafe { #_const.enable() }
        }

        pub fn #hook_disable() -> crochet::detour::Result<()> {
            unsafe { #_const.disable() }
        }

        pub fn #hook_is_enabled() -> bool {
            #_const.is_enabled()
        }
    ).into()
}

/// Enables a previously defined dynamic library hook.
///
/// # Example
///
/// ```rust
/// fn enable_hooks() {
///    crochet::enable!(simple_hook);
/// }
/// ```
///
/// # Attributes
///
/// - `hook`: the path of the hook function to enable.
///
/// # See also
///
/// - [`crochet::hook`](./attr.hook.html)
/// - [`crochet::disable!`](./macro.disable.html)
/// - [`crochet::is_enabled!`](./macro.is_enabled.html)
#[proc_macro]
pub fn enable(attrs: TokenStream) -> TokenStream {
    let mut hook = parse_macro_input!(attrs as ExprPath);

    let last_seg = hook.path.segments.iter_mut().last().unwrap();

    last_seg.ident = quote::format_ident!("{}_crochet_enable", last_seg.ident);
    quote!(
        #hook()
    )
        .into()
}

/// Disables a previously defined dynamic library hook.
///
/// # Example
///
/// ```rust
/// fn disable_hooks() {
///    crochet::disable!(simple_hook);
/// }
/// ```
///
/// # Attributes
///
/// - `hook`: the path of the hook function to disable.
///
/// # See also
///
/// - [`crochet::hook`](./attr.hook.html)
/// - [`crochet::enable!`](./macro.enable.html)
/// - [`crochet::is_enabled!`](./macro.is_enabled.html)
#[proc_macro]
pub fn disable(attrs: TokenStream) -> TokenStream {
    let mut hook = parse_macro_input!(attrs as ExprPath);

    let last_seg = hook.path.segments.iter_mut().last().unwrap();

    last_seg.ident = quote::format_ident!("{}_crochet_disable", last_seg.ident);
    quote!(
        #hook()
    )
        .into()
}

/// Checks if a previously defined dynamic library hook is enabled.
///
/// # Example
///
/// ```rust
/// fn check_hooks() {
///     if crochet::is_enabled!(simple_hook) {
///         println!("Hooked!");
///     } else {
///         println!("Not hooked!");
///     }
/// }
/// ```
///
/// # Attributes
///
/// - `hook`: the path of the hook function to check.
///
/// # See also
///
/// - [`crochet::hook`](./attr.hook.html)
/// - [`crochet::enable!`](./macro.enable.html)
/// - [`crochet::disable!`](./macro.disable.html)
#[proc_macro]
pub fn is_enabled(attrs: TokenStream) -> TokenStream {
    let mut hook = parse_macro_input!(attrs as syn::ExprPath);

    let last_seg = hook.path.segments.iter_mut().last().unwrap();

    last_seg.ident = quote::format_ident!("{}_crochet_is_enabled", last_seg.ident);
    quote!(
        #hook()
    )
        .into()
}
