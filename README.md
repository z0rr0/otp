# OTP

![Go](https://github.com/z0rr0/otp/workflows/Go/badge.svg)
![Python](https://github.com/z0rr0/otp/workflows/Python/badge.svg)
![Rust](https://github.com/z0rr0/otp/workflows/Rust/badge.svg)
![License](https://img.shields.io/github/license/z0rr0/otp.svg)

One time password examples.

Every language library/package contains public methods `secret` and `code`.

## Tests

### Go

```shell
cd go
go test -v -bench=.
```

### Python

```shell
cd python
python3 -m unittest -v test_otp
```

### Rust

```shell
cd rust/otp
cargo test -- --nocapture
```