<https://developer.mozilla.org/zh-CN/docs/WebAssembly/Guides/Rust_to_Wasm>
最新文档 <https://github.com/wasm-bindgen/wasm-bindgen>

// rust编译wasm
wasm-pack build --scope linqining --target web

// wasm-pack build --scope linqining --target no-modules 纯js

//发布npm
npm publish --access=public

