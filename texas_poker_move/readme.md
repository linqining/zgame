// kill sui process
pkill -9 -f sui

交叉编译
cargo zigbuild --release --target x86_64-unknown-linux-musl
