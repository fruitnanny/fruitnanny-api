# FruitNanny API

This is the HTTP API for the [FruitNanny](https://fruitnanny.github.io/)
project written in [Go](https://golang.org/).


## Building

The API is bundled in a Debian package which can be cross-compiled for the
`armhf` architecture.

```bash
# Build for the host architecture
make build

# Cross-compile for Raspberry Pi
make crossdeb
```
