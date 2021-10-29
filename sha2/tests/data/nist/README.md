### Additional test vectors from NIST validation program


Homepage: https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing#shavs

#### Prepare NIST short and long vectors.


1. Get and unzip test vectors:

```sh
wget https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip
unzip shabytetestvectors.zip
```

2. Clone nessesary version of blobby convert utility example for encoding:

```sh
git clone https://github.com/RustCrypto/utils
cd utils
git checkout blobby-v0.1.2
```

3. Convert `LongMsg` and `ShortMsg` kinds of rsp files to format consumable by blobby convert enncoder:


```sh
python convert_rsp_to_blb_input_txt.py
```

```
"sha224_input.txt" with 129 test vectors generated.
"sha256_input.txt" with 129 test vectors generated.
"sha384_input.txt" with 257 test vectors generated.
"sha512_input.txt" with 257 test vectors generated.
```


should generated **sha\*\*_input.txt**

4. Encode as `blobby` binary format acceptable by sha2/tests digest test cases:

```sh
cargo run --manifest-path utils/blobby/Cargo.toml --example convert encode sha224_input.txt ../sha224_nist_shortlong.blb
cargo run --manifest-path utils/blobby/Cargo.toml --example convert encode sha256_input.txt ../sha256_nist_shortlong.blb
cargo run --manifest-path utils/blobby/Cargo.toml --example convert encode sha384_input.txt ../sha384_nist_shortlong.blb
cargo run --manifest-path utils/blobby/Cargo.toml --example convert encode sha512_input.txt ../sha512_nist_shortlong.blb
```

outputs:
```
Processed 258 record(s)
Processed 258 record(s)
Processed 514 record(s)
Processed 514 record(s)
```

5. Finally run the extended set of tests.

```sh
cargo test --tests nist_shortlong
```

outputs:
```
    Finished test [optimized + debuginfo] target(s) in 0.02s
     Running unittests (/root/filecoin/hashes/target/debug/deps/sha2-0813bb0132f7a7c7)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/lib.rs (/root/filecoin/hashes/target/debug/deps/lib-74caf76f52224d1a)

running 4 tests
test sha224_nist_shortlong ... ok
test sha256_nist_shortlong ... ok
test sha512_nist_shortlong ... ok
test sha384_nist_shortlong ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.28s
```
