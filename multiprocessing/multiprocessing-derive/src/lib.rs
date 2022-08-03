#[macro_use]
extern crate quote;

use proc_macro::TokenStream;
use quote::ToTokens;
use syn::parse_macro_input;
use syn::DeriveInput;

#[proc_macro_attribute]
pub fn entrypoint(_meta: TokenStream, input: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(input as syn::ItemFn);

    let tokio_attr_index = input.attrs.iter().position(|attr| {
        let path = &attr.path;
        (quote! {#path}).to_string().contains("tokio :: main")
    });
    let tokio_attr = tokio_attr_index.map(|i| input.attrs.remove(i));

    let return_type = match input.sig.output {
        syn::ReturnType::Default => quote! { () },
        syn::ReturnType::Type(_, ref ty) => quote! { #ty },
    };

    let generic_params = &input.sig.generics;
    let generics = {
        let params: Vec<_> = input
            .sig
            .generics
            .params
            .iter()
            .map(|param| match param {
                syn::GenericParam::Type(ref ty) => ty.ident.to_token_stream(),
                syn::GenericParam::Lifetime(ref lt) => lt.lifetime.to_token_stream(),
                syn::GenericParam::Const(ref con) => con.ident.to_token_stream(),
            })
            .collect();
        quote! { <#(#params,)*> }
    };
    let generic_phantom: Vec<_> = input
        .sig
        .generics
        .params
        .iter()
        .enumerate()
        .map(|(i, param)| {
            let field = format_ident!("f{}", i);
            match param {
                syn::GenericParam::Type(ref ty) => {
                    let ident = &ty.ident;
                    quote! { #field: std::marker::PhantomData<fn(#ident) -> #ident> }
                }
                syn::GenericParam::Lifetime(ref lt) => {
                    let lt = &lt.lifetime;
                    quote! { #field: std::marker::PhantomData<& #lt ()> }
                }
                syn::GenericParam::Const(ref _con) => {
                    unimplemented!()
                }
            }
        })
        .collect();
    let generic_phantom_build: Vec<_> = (0..input.sig.generics.params.len())
        .map(|i| {
            let field = format_ident!("f{}", i);
            quote! { #field: std::marker::PhantomData }
        })
        .collect();

    // Pray all &input are distinct
    let link_name = format!(
        "multiprocessing_{}_{:?}",
        input.sig.ident.to_string(),
        &input as *const syn::ItemFn
    );

    let type_ident = format_ident!("T_{}", link_name);
    let entry_ident = format_ident!("E_{}", link_name);

    let ident = input.sig.ident;
    input.sig.ident = format_ident!("call");

    let vis = input.vis;
    input.vis = syn::Visibility::Public(syn::VisPublic {
        pub_token: <syn::Token![pub] as std::default::Default>::default(),
    });

    let args = &input.sig.inputs;

    let mut fn_args = Vec::new();
    let mut fn_types = Vec::new();
    let mut extracted_args = Vec::new();
    let mut arg_names = Vec::new();
    let mut args_from_tuple = Vec::new();
    let mut binding = Vec::new();
    for (i, arg) in args.iter().enumerate() {
        let i = syn::Index::from(i);
        if let syn::FnArg::Typed(pattype) = arg {
            if let syn::Pat::Ident(ref patident) = *pattype.pat {
                let ident = &patident.ident;
                let colon_token = &pattype.colon_token;
                let ty = &pattype.ty;
                fn_args.push(quote! { #ident #colon_token #ty });
                fn_types.push(quote! { #ty });
                extracted_args.push(quote! { multiprocessing_args.#ident });
                arg_names.push(quote! { #ident });
                args_from_tuple.push(quote! { args.#i });
                binding.push(quote! { .bind(#ident) });
            } else {
                unreachable!();
            }
        } else {
            unreachable!();
        }
    }

    let bound = if args.len() == 0 {
        quote! { #ident }
    } else {
        let head_ty = &fn_types[0];
        let tail_ty = &fn_types[1..];
        let head_arg = &arg_names[0];
        let tail_binding = &binding[1..];
        quote! {
            Bind::<#head_ty, (#(#tail_ty,)*)>::bind(Box::new(#ident), #head_arg) #(#tail_binding)*
        }
    };

    let return_type_wrapped;
    let async_;
    let pin;
    let dot_await;
    let ns_tokio;
    if tokio_attr.is_some() {
        return_type_wrapped = quote! { ::std::pin::Pin<::std::boxed::Box<dyn ::std::future::Future<Output = #return_type>>> };
        async_ = quote! { async };
        pin = quote! { Box::pin };
        dot_await = quote! { .await };
        ns_tokio = quote! { ::tokio };
    } else {
        return_type_wrapped = return_type.clone();
        async_ = quote! {};
        pin = quote! {};
        dot_await = quote! {};
        ns_tokio = quote! {};
    }

    let expanded = quote! {
        #[derive(::multiprocessing::Object)]
        struct #entry_ident #generic_params {
            func: ::multiprocessing::Delayed<::std::boxed::Box<dyn ::multiprocessing::FnOnce<(), Output = #return_type_wrapped>>>,
            #(#generic_phantom,)*
        }

        impl #generic_params #entry_ident #generics {
            fn new(func: ::std::boxed::Box<dyn ::multiprocessing::FnOnce<(), Output = #return_type_wrapped>>) -> Self {
                Self {
                    func: ::multiprocessing::Delayed::new(func),
                    #(#generic_phantom_build,)*
                }
            }
        }

        impl #generic_params ::multiprocessing::Entrypoint<(::std::os::unix::io::RawFd,)> for #entry_ident #generics {
            type Output = i32;
            #tokio_attr
            #[allow(unreachable_code)] // If func returns !
            #async_ fn call(self, args: (::std::os::unix::io::RawFd,)) -> Self::Output {
                let output_tx_fd = args.0;
                use ::std::os::unix::io::FromRawFd;
                let mut output_tx = unsafe {
                    ::multiprocessing #ns_tokio ::Sender::<#return_type>::from_raw_fd(output_tx_fd)
                };
                output_tx.send(&self.func.deserialize()() #dot_await)
                    #dot_await
                    .expect("Failed to send subprocess output");
                0
            }
        }

        impl #generic_params ::multiprocessing::Entrypoint<(#(#fn_types,)*)> for #type_ident {
            type Output = #return_type_wrapped;
            fn call(self, args: (#(#fn_types,)*)) -> Self::Output {
                #pin(#type_ident::call(#(#args_from_tuple,)*))
            }
        }

        #[allow(non_camel_case_types)]
        #[derive(::multiprocessing::Object)]
        #vis struct #type_ident;

        impl #type_ident {
            #[link_name = #link_name]
            #input

            pub unsafe fn spawn_with_flags #generic_params(&self, flags: ::multiprocessing::libc::c_int, #(#fn_args,)*) -> ::std::io::Result<::multiprocessing::Child<#return_type>> {
                use ::multiprocessing::Bind;
                ::multiprocessing::spawn(Box::new(::multiprocessing::EntrypointWrapper(#entry_ident::new(Box::new(#bound)))), flags)
            }

            pub async unsafe fn spawn_with_flags_tokio #generic_params(&self, flags: ::multiprocessing::libc::c_int, #(#fn_args,)*) -> ::std::io::Result<::multiprocessing::tokio::Child<#return_type>> {
                use ::multiprocessing::Bind;
                ::multiprocessing::tokio::spawn(Box::new(::multiprocessing::EntrypointWrapper(#entry_ident::new(Box::new(#bound)))), flags).await
            }

            pub fn spawn #generic_params(&self, #(#fn_args,)*) -> ::std::io::Result<::multiprocessing::Child<#return_type>> {
                unsafe { self.spawn_with_flags(0, #(#arg_names,)*) }
            }

            pub async fn spawn_tokio #generic_params(&self, #(#fn_args,)*) -> ::std::io::Result<::multiprocessing::tokio::Child<#return_type>> {
                unsafe { self.spawn_with_flags_tokio(0, #(#arg_names,)*) }.await
            }
        }

        #[allow(non_upper_case_globals)]
        #vis const #ident: ::multiprocessing::EntrypointWrapper<#type_ident> = ::multiprocessing::EntrypointWrapper(#type_ident);
    };

    TokenStream::from(expanded)
}

#[proc_macro_attribute]
pub fn main(_meta: TokenStream, input: TokenStream) -> TokenStream {
    let mut input = parse_macro_input!(input as syn::ItemFn);

    input.sig.ident = syn::Ident::new("multiprocessing_old_main", input.sig.ident.span());

    let expanded = quote! {
        #input

        #[::multiprocessing::imp::ctor]
        fn multiprocessing_add_main() {
            *::multiprocessing::imp::MAIN_ENTRY
                .write()
                .expect("Failed to acquire write access to MAIN_ENTRY") = Some(|| {
                ::multiprocessing::imp::Report::report(multiprocessing_old_main())
            });
        }

        fn main() {
            ::multiprocessing::imp::main()
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_derive(Object)]
pub fn derive_object(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let ident = &input.ident;

    let generics = {
        let params: Vec<_> = input
            .generics
            .params
            .iter()
            .map(|param| match param {
                syn::GenericParam::Type(ref ty) => ty.ident.to_token_stream(),
                syn::GenericParam::Lifetime(ref lt) => lt.lifetime.to_token_stream(),
                syn::GenericParam::Const(ref con) => con.ident.to_token_stream(),
            })
            .collect();
        quote! { <#(#params,)*> }
    };

    let generic_params = &input.generics.params;
    let generics_impl = quote! { <#generic_params> };

    let generics_where = input.generics.where_clause;

    let expanded = match input.data {
        syn::Data::Struct(struct_) => match struct_.fields {
            syn::Fields::Named(fields) => {
                let serialize_fields = fields.named.iter().map(|field| {
                    let ident = &field.ident;
                    quote! {
                        s.serialize(&self.#ident);
                    }
                });
                let deserialize_fields = fields.named.iter().map(|field| {
                    let ident = &field.ident;
                    quote! {
                        #ident: d.deserialize(),
                    }
                });
                quote! {
                    impl #generics_impl ::multiprocessing::Object for #ident #generics #generics_where {
                        fn serialize_self(&self, s: &mut ::multiprocessing::Serializer) {
                            #(#serialize_fields)*
                        }
                        fn deserialize_self(d: &mut ::multiprocessing::Deserializer) -> Self {
                            Self {
                                #(#deserialize_fields)*
                            }
                        }
                        fn deserialize_on_heap<'serde>(&self, d: &mut ::multiprocessing::Deserializer) -> ::std::boxed::Box<dyn ::multiprocessing::Object + 'serde> where Self: 'serde {
                            use ::multiprocessing::Object;
                            ::std::boxed::Box::new(Self::deserialize_self(d))
                        }
                    }
                }
            }
            syn::Fields::Unnamed(fields) => {
                let serialize_fields = fields.unnamed.iter().enumerate().map(|(i, _)| {
                    let i = syn::Index::from(i);
                    quote! {
                        s.serialize(&self.#i);
                    }
                });
                let deserialize_fields = fields.unnamed.iter().map(|_| {
                    quote! {
                        d.deserialize(),
                    }
                });
                quote! {
                    impl #generics_impl ::multiprocessing::Object for #ident #generics #generics_where {
                        fn serialize_self(&self, s: &mut ::multiprocessing::Serializer) {
                            #(#serialize_fields)*
                        }
                        fn deserialize_self(d: &mut ::multiprocessing::Deserializer) -> Self {
                            Self(
                                #(#deserialize_fields)*
                            )
                        }
                        fn deserialize_on_heap<'serde>(&self, d: &mut ::multiprocessing::Deserializer) -> ::std::boxed::Box<dyn ::multiprocessing::Object + 'serde> where Self: 'serde {
                            use ::multiprocessing::Object;
                            ::std::boxed::Box::new(Self::deserialize_self(d))
                        }
                    }
                }
            }
            syn::Fields::Unit => {
                quote! {
                    impl #generics_impl ::multiprocessing::Object for #ident #generics #generics_where {
                        fn serialize_self(&self, s: &mut ::multiprocessing::Serializer) {
                        }
                        fn deserialize_self(d: &mut ::multiprocessing::Deserializer) -> Self {
                            Self
                        }
                        fn deserialize_on_heap<'serde>(&self, d: &mut ::multiprocessing::Deserializer) -> ::std::boxed::Box<dyn ::multiprocessing::Object + 'serde> where Self: 'serde {
                            use ::multiprocessing::Object;
                            ::std::boxed::Box::new(Self::deserialize_self(d))
                        }
                    }
                }
            }
        },
        syn::Data::Enum(enum_) => {
            let serialize_variants = enum_.variants.iter().enumerate().map(|(i, variant)| {
                let ident = &variant.ident;
                match &variant.fields {
                    syn::Fields::Named(fields) => {
                        let (refs, sers): (Vec<_>, Vec<_>) = fields
                            .named
                            .iter()
                            .map(|field| {
                                let ident = &field.ident;
                                (quote! { ref #ident }, quote! { s.serialize(#ident); })
                            })
                            .unzip();
                        quote! {
                            Self::#ident{ #(#refs,)* } => {
                                s.serialize(&(#i as usize));
                                #(#sers)*
                            }
                        }
                    }
                    syn::Fields::Unnamed(fields) => {
                        let (refs, sers): (Vec<_>, Vec<_>) = (0..fields.unnamed.len())
                            .map(|i| {
                                let ident = format_ident!("a{}", i);
                                (quote! { ref #ident }, quote! { s.serialize(#ident); })
                            })
                            .unzip();
                        quote! {
                            Self::#ident(#(#refs,)*) => {
                                s.serialize(&(#i as usize));
                                #(#sers)*
                            }
                        }
                    }
                    syn::Fields::Unit => {
                        quote! {
                            Self::#ident => {
                                s.serialize(&(#i as usize));
                            }
                        }
                    }
                }
            });
            let deserialize_variants = enum_.variants.iter().enumerate().map(|(i, variant)| {
                let ident = &variant.ident;

                match &variant.fields {
                    syn::Fields::Named(fields) => {
                        let des: Vec<_> = fields
                            .named
                            .iter()
                            .map(|field| {
                                let ident = &field.ident;
                                quote! { #ident: d.deserialize() }
                            })
                            .collect();
                        quote! { #i => Self::#ident{ #(#des,)* } }
                    }
                    syn::Fields::Unnamed(fields) => {
                        let des: Vec<_> = (0..fields.unnamed.len())
                            .map(|_| quote! { d.deserialize() })
                            .collect();
                        quote! { #i => Self::#ident(#(#des,)*) }
                    }
                    syn::Fields::Unit => {
                        quote! { #i => Self::#ident }
                    }
                }
            });
            quote! {
                impl #generics_impl ::multiprocessing::Object for #ident #generics #generics_where {
                    fn serialize_self(&self, s: &mut ::multiprocessing::Serializer) {
                        match self {
                            #(#serialize_variants,)*
                        }
                    }
                    fn deserialize_self(d: &mut ::multiprocessing::Deserializer) -> Self {
                        match d.deserialize::<usize>() {
                            #(#deserialize_variants,)*
                            _ => panic!("Unexpected enum variant"),
                        }
                    }
                    fn deserialize_on_heap<'serde>(&self, d: &mut ::multiprocessing::Deserializer) -> ::std::boxed::Box<dyn ::multiprocessing::Object + 'serde> where Self: 'serde {
                        use ::multiprocessing::Object;
                        ::std::boxed::Box::new(Self::deserialize_self(d))
                    }
                }
            }
        }
        syn::Data::Union(_) => unimplemented!(),
    };

    TokenStream::from(expanded)
}
