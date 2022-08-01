use crate::{Object, TraitObject};
use paste::paste;
use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;

pub trait Entrypoint<Args>: Object {
    type Output;
    fn call(self, args: Args) -> Self::Output;
}

#[derive(Object)]
pub struct EntrypointWrapper<T: Object>(pub T);

impl<T: Object> Deref for EntrypointWrapper<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<Args, T: Entrypoint<Args>> std::ops::FnOnce<Args> for EntrypointWrapper<T> {
    type Output = T::Output;
    extern "rust-call" fn call_once(self, args: Args) -> Self::Output {
        self.0.call(args)
    }
}

pub trait FnOnce<Args>: std::ops::FnOnce<Args> + TraitObject {}
pub trait Fn<Args>: std::ops::Fn<Args> + TraitObject {}
pub trait FnMut<Args>: std::ops::FnMut<Args> + TraitObject {}

impl<Args, T: std::ops::FnOnce<Args> + TraitObject> FnOnce<Args> for T {}
impl<Args, T: std::ops::Fn<Args> + TraitObject> Fn<Args> for T {}
impl<Args, T: std::ops::FnMut<Args> + TraitObject> FnMut<Args> for T {}

pub trait Bind<Head: Object, Tail> {
    fn bind(self, head: Head) -> Bound<Self, Head>
    where
        Self: Sized + Object;
}

#[derive(Object)]
pub struct Bound<Func: Object, Head: Object> {
    pub func: Func,
    pub head: Head,
}

macro_rules! reverse {
    ([$($acc:tt)*]) => { ($($acc)*) };
    ([$($acc:tt)*] $single:tt) => { reverse!([$single, $($acc)*]) };
    ([$($acc:tt)*] $head:tt, $($tail:tt),*) => { reverse!([$head, $($acc)*] $($tail),*) };
}

macro_rules! decl_fn {
    () => {};

    ($head:tt $($tail:tt)*) => {
        decl_fn!($($tail)*);

        paste! {
            impl<[<T $head>]: Object $(, [<T $tail>])*, Func: std::ops::FnOnce<([<T $head>], $([<T $tail>]),*)> + Object> Bind<[<T $head>], ($([<T $tail>],)*)> for Func {
                fn bind(self, head: [<T $head>]) -> Bound<Self, [<T $head>]> {
                    Bound {
                        func: self,
                        head,
                    }
                }
            }

            impl<[<T $head>]: Object $(, [<T $tail>])*, Func: std::ops::FnOnce<([<T $head>], $([<T $tail>]),*)> + Object> std::ops::FnOnce<($([<T $tail>],)*)> for Bound<Func, [<T $head>]> {
                type Output = Func::Output;

                #[allow(unused_variables)]
                extern "rust-call" fn call_once(self, args: ($([<T $tail>],)*)) -> Self::Output {
                    self.func.call_once(reverse!([] $((args.$tail),)* (self.head)))
                }
            }

            impl<[<T $head>]: Object + Copy $(, [<T $tail>])*, Func: std::ops::Fn<([<T $head>], $([<T $tail>]),*)> + Object> std::ops::Fn<($([<T $tail>],)*)> for Bound<Func, [<T $head>]> {
                #[allow(unused_variables)]
                extern "rust-call" fn call(&self, args: ($([<T $tail>],)*)) -> Self::Output {
                    self.func.call(reverse!([] $((args.$tail),)* (self.head)))
                }
            }

            impl<[<T $head>]: Object + Copy $(, [<T $tail>])*, Func: std::ops::FnMut<([<T $head>], $([<T $tail>]),*)> + Object> std::ops::FnMut<($([<T $tail>],)*)> for Bound<Func, [<T $head>]> {
                #[allow(unused_variables)]
                extern "rust-call" fn call_mut(&mut self, args: ($([<T $tail>],)*)) -> Self::Output {
                    self.func.call_mut(reverse!([] $((args.$tail),)* (self.head)))
                }
            }
        }
    }
}

decl_fn!(x 19 18 17 16 15 14 13 12 11 10 9 8 7 6 5 4 3 2 1 0);

pub trait Await<T> {}

impl<T> Await<T> for Pin<Box<dyn Future<Output = T>>> {}

impl<T> Await<T> for T {}
