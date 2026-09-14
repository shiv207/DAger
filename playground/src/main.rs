//! Deliberately vulnerable playground for exercising DAGger's fix flow —
//! not part of the DAGger workspace, and not meant to be depended on.
//!
//! Both pinned dependencies have real, live OSV.dev advisories:
//!   - `lru = 0.12.5` has patched versions listed -> exercises the
//!     version-bump auto-fix path.
//!   - `paste = 1.0.15` is unmaintained with no patched version listed ->
//!     exercises the Groq mitigation-suggestion fallback path.
//!
//! Both are actually referenced below (not just declared in Cargo.toml) so
//! DAGger's `use`-declaration reachability pass marks them used, not dead.

use lru::LruCache;
use paste::paste;
use std::num::NonZeroUsize;

paste! {
    pub fn [<say_ hello>]() {
        println!("paste macro expanded this function name at compile time");
    }
}

fn main() {
    let mut cache: LruCache<&str, i32> = LruCache::new(NonZeroUsize::new(2).unwrap());
    cache.put("a", 1);
    cache.put("b", 2);
    println!("lru cache get(\"a\") = {:?}", cache.get(&"a"));

    say_hello();
}
