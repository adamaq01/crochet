use convert_case::{Case, Casing};
use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{quote, ToTokens};
use syn::{
    parse::Parse, parse_macro_input, parse_quote, token, AttrStyle, ExprPath, Ident, LitBool,
    LitStr, Stmt, Token,
};
use syn::spanned::Spanned;

mod kw {
    syn::custom_keyword!(library);
    syn::custom_keyword!(symbol);
    syn::custom_keyword!(compile_check);
    syn::custom_keyword!(_self);
    syn::custom_keyword!(self_);
    syn::custom_keyword!(this);
}

#[derive(Clone)]
enum StrOrSelf {
    SelfValue(Span),
    LitStr(LitStr),
}

impl StrOrSelf {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let look = input.lookahead1();
        if look.peek(Token![self]) {
            input.parse::<Token![self]>().map(|token| token.span()).map(Self::SelfValue)
        } else if look.peek(kw::_self) {
            input.parse::<kw::_self>().map(|token| token.span()).map(Self::SelfValue)
        } else if look.peek(kw::self_) {
            input.parse::<kw::self_>().map(|token| token.span()).map(Self::SelfValue)
        } else if look.peek(kw::this) {
            input.parse::<kw::this>().map(|token| token.span()).map(Self::SelfValue)
        } else {
            input.parse::<LitStr>().map(Self::LitStr)
        }
    }

    #[allow(dead_code)]
    fn is_self(&self) -> bool {
        match self {
            Self::SelfValue(_) => true,
            Self::LitStr(_) => false,
        }
    }

    fn is_lit(&self) -> bool {
        match self {
            Self::SelfValue(_) => false,
            Self::LitStr(_) => true,
        }
    }

    fn unwrap_lit(self) -> LitStr {
        match self {
            Self::SelfValue(_) => panic!("Cannot unwrap self"),
            Self::LitStr(lit) => lit,
        }
    }

    fn span(&self) -> Span {
        match self {
            Self::SelfValue(self_value) => *self_value,
            Self::LitStr(lit) => lit.span(),
        }
    }
}

struct HookAttrs {
    library: StrOrSelf,
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
                library = Some(StrOrSelf::parse(input)?);
                if symbol.is_none() && unknown.is_some() && unknown.as_ref().is_some_and(StrOrSelf::is_lit) {
                    symbol = Some(unknown.unwrap().unwrap_lit());
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
                unknown = Some(StrOrSelf::parse(input)?);
            } else if symbol.is_none() {
                symbol = Some(input.parse::<LitStr>()?);
            } else if library.is_none() {
                library = Some(StrOrSelf::parse(input)?);
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
            } else if library.is_some() && unknown.is_lit() {
                symbol = Some(unknown.unwrap_lit());
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

struct LoadAttrs {
    library: LitStr,
    compile_check: bool,
}

impl Parse for LoadAttrs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut library = None;
        let mut compile_check = false;
        while !input.is_empty() {
            let look = input.lookahead1();
            if look.peek(kw::library) {
                input.parse::<kw::library>()?;
                input.parse::<Token![=]>()?;
                library = Some(input.parse::<LitStr>()?);
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

        if let Some(library) = library {
            Ok(LoadAttrs {
                library,
                compile_check,
            })
        } else {
            Err(syn::Error::new(
                Span::call_site(),
                "Missing library",
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

fn open_library(token: StrOrSelf) -> Result<dlopen2::raw::Library, dlopen2::Error> {
    match token {
        StrOrSelf::SelfValue(_) => dlopen2::raw::Library::open_self(),
        StrOrSelf::LitStr(lit) => dlopen2::raw::Library::open(lit.value())
    }
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
/// - `library`: the name of the dynamic library to hook or one of `self`, `_self`, `self_` or `this`.
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

    // extern "system"
    if mod_fn.sig.abi.is_none() {
        mod_fn.sig.abi = Some(syn::Abi {
            extern_token: syn::token::Extern {
                span: Span::call_site(),
            },
            name: Some(LitStr::new("system", Span::call_site())),
        });
    }

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
                    ::core::mem::transmute::<_, extern "system" fn(#(#args_tokens),*) #return_tokens>(
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
            open_library(library.clone())
                .map_err(|e| syn::Error::new(Span::call_site(), e))?
                .symbol::<*const ()>(symbol.value().as_str())
                .map_err(|e| syn::Error::new(Span::call_site(), e))?;

            Ok(())
        })();
        if let Err(e) = result {
            return e.to_compile_error().into();
        }
    }

    let open_library = match library {
        StrOrSelf::SelfValue(_) => quote!(crochet::dlopen2::raw::Library::open_self()),
        StrOrSelf::LitStr(lit) => quote!(crochet::dlopen2::raw::Library::open(#lit)),
    };

    quote!(
        crochet::lazy_static::lazy_static! {
            static ref #_const: crochet::detour::RawDetour = unsafe {
                let symbol = #open_library
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

///
///
/// # Example
///
/// ```rust
/// #[crochet::load("library.so", compile_check)]
/// extern "system" {
///     #[symbol("a_function")]
///     fn my_super_function(); // Resolves to `a_function` in `library.so`
///     fn another_function();
/// }
/// ```
///
/// # Attributes
///
/// - `library`: the name of the dynamic library to load.
/// - `compile_check`: whether to check if the library and symbol are available at compile time.
/// - `symbol`: the name of the function to load.
///
/// The macro attributes syntax is very flexible as it follows the same rules as the [`#[crochet::hook]` attribute](./macro.hook.html).
///
/// # Panics
///
/// Panics if the dynamic library or the function cannot be found at runtime.
#[proc_macro_attribute]
pub fn load(attrs: TokenStream, input: TokenStream) -> TokenStream {
    let mod_foreign = parse_macro_input!(input as syn::ItemForeignMod);
    let attrs = parse_macro_input!(attrs as LoadAttrs);
    let library = attrs.library;
    let compile_check = attrs.compile_check;

    let mut symbols = Vec::new();
    for item in mod_foreign.items {
        if let syn::ForeignItem::Fn(mod_fn) = item {
            if mod_fn.attrs.len() > 1 || (mod_fn.attrs.len() == 1 && !mod_fn.attrs[0].path.is_ident("symbol")) {
                return syn::Error::new(
                    mod_fn.span(),
                    "Only symbol attribute is allowed here",
                ).to_compile_error().into();
            }

            let (symbol, span) = {
                let symbol = mod_fn.attrs.first().map(|attr| {
                    let lit = attr.parse_args::<LitStr>()
                        .map_err(|_| syn::Error::new(attr.span(), "Invalid symbol attribute").to_compile_error())?;

                    Ok((lit.value(), attr.tokens.span()))
                }).unwrap_or_else(|| Ok((mod_fn.sig.ident.to_string(), mod_fn.sig.ident.span())));

                if let Ok((symbol, span)) = symbol {
                    (symbol, span)
                } else {
                    return symbol.unwrap_err();
                }
            };

            if compile_check {
                let result: syn::Result<()> = (|| unsafe {
                    dlopen2::raw::Library::open(library.value())
                        .map_err(|e| syn::Error::new(Span::call_site(), e))?
                        .symbol::<*const ()>(symbol.as_str())
                        .map_err(|e| syn::Error::new(span, e))?;

                    Ok(())
                })();
                if let Err(e) = result {
                    return e.to_compile_error().into();
                }
            }

            symbols.push(Symbol {
                symbol: LitStr::new(symbol.as_str(), mod_fn.sig.ident.span()),
                visibility: mod_fn.vis,
                signature: mod_fn.sig,
            });
        } else {
            return syn::Error::new(item.span(), "Only functions are supported in crochet::load!").to_compile_error().into();
        }
    }

    let _const = Ident::new(
        format!(
            "_{}",
            library.value()
                .replace('.', "_")
                .to_case(Case::UpperSnake)
        )
            .as_str(),
        Span::call_site(),
    );

    let _type = Ident::new(
        format!(
            "_{}",
            library.value()
                .replace('.', "_")
                .to_case(Case::Pascal)
        )
            .as_str(),
        Span::call_site(),
    );
    let symbols = Symbols(_type.clone(), symbols);

    let mut tokens_declaration = proc_macro2::TokenStream::new();
    if let Err(e) = symbols.to_tokens(Phase::StructDeclaration, &mut tokens_declaration) {
        return e.into();
    }

    let mut tokens_definition = proc_macro2::TokenStream::new();
    if let Err(e) = symbols.to_tokens(Phase::StructDefinition, &mut tokens_definition) {
        return e.into();
    }

    let mut tokens_func_definitions = proc_macro2::TokenStream::new();
    if let Err(e) = symbols.to_tokens(Phase::FunctionDefinition { _const: _const.clone() }, &mut tokens_func_definitions) {
        return e.into();
    }

    quote!(
        #[allow(missing_copy_implementations)]
        #[allow(non_camel_case_types)]
        #tokens_declaration

        crochet::lazy_static::lazy_static! {
            static ref #_const: #_type = unsafe {
                let library = crochet::dlopen2::raw::Library::open(#library)
                    .expect("Could not open library");

                #tokens_definition
            };
        }

        #tokens_func_definitions
    ).into()
}

#[derive(Debug, Clone)]
enum Phase {
    StructDeclaration,
    StructDefinition,
    FunctionDefinition {
        _const: Ident,
    },
}

struct Symbol {
    symbol: syn::LitStr,
    visibility: syn::Visibility,
    signature: syn::Signature,
}

impl Symbol {
    fn to_tokens(&self, phase: Phase, tokens: &mut proc_macro2::TokenStream) -> Result<(), TokenStream2> {
        let ident = self.signature.ident.clone();
        let args_tokens = self.signature.inputs.iter().map(remove_mut);
        let return_tokens = self.signature.output.to_token_stream();
        let signature = self.signature.clone();
        let _const = Ident::new("_const", Span::call_site());
        let err_message = LitStr::new(format!("Could not find symbol {}", self.symbol.value()).as_str(), Span::call_site());

        match phase {
            Phase::StructDeclaration => {
                quote!(
                    #ident: extern "system" fn(#(#args_tokens),*) #return_tokens,
                ).to_tokens(tokens);
            }
            Phase::StructDefinition => {
                let symbol = self.symbol.clone();
                quote!(
                    #ident: library.symbol::<extern "system" fn(#(#args_tokens),*) #return_tokens>(#symbol)
                        .expect(#err_message),
                ).to_tokens(tokens);
            }
            Phase::FunctionDefinition { _const } => {
                let visibility = self.visibility.clone();
                let mut args_names = Vec::with_capacity(self.signature.inputs.len());
                for arg in self.signature.inputs.clone() {
                    let mut pushed = false;
                    if let syn::FnArg::Typed(syn::PatType { pat, .. }) = arg {
                        if let syn::Pat::Ident(syn::PatIdent { ident, .. }) = *pat {
                            args_names.push(ident);
                            pushed = true;
                        }
                    }
                    if !pushed {
                        return Err(syn::Error::new(signature.span(), "Invalid argument").to_compile_error());
                    }
                }
                quote!(
                    #visibility unsafe fn #ident(#(#args_tokens),*) #return_tokens {
                        (#_const.#ident)(#(#args_names),*)
                    }
                ).to_tokens(tokens);
            }
        }

        Ok(())
    }
}

struct Symbols(Ident, Vec<Symbol>);

impl Symbols {
    fn to_tokens(&self, phase: Phase, tokens: &mut proc_macro2::TokenStream) -> Result<(), TokenStream2> {
        let ident = self.0.clone();

        let mut stream = TokenStream2::new();
        for symbol in &self.1 {
            symbol.to_tokens(phase.clone(), &mut stream)?;
        }

        match phase {
            Phase::StructDeclaration => {
                quote!(
                    struct #ident {
                        #stream
                    }
                ).to_tokens(tokens);
            }
            Phase::StructDefinition => {
                quote!(
                    #ident {
                        #stream
                    }
                ).to_tokens(tokens);
            }
            Phase::FunctionDefinition { _const } => {
                tokens.extend(stream);
            }
        }

        Ok(())
    }
}
