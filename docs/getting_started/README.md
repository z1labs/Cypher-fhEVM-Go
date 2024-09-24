# Getting started

In order to use the library, you need to clone the repository and build it. This is required because the library depends on the `tfhe-rs` library that needs to be built from source (for now), and Go doesn't support such a build.

```bash
$ git clone https://github.com/zama-ai/fhevm-go
$ cd fhevm-go
$ make build
```

You can now use it in your project by adding it to `go.mod`, and adding a `replace` to point to your local build. An example using `fhevm-go` v1.0.0:

```go
...
require(
    ...
    github.com/zama-ai/fhevm-go v1.0.0
    ...
)

replace(
    ...
    github.com/zama-ai/fhevm-go v1.0.0 => /path/to/your/local/fhevm-go
    ...
)
...
```

{% hint style="info" %}
The replace is necessary for now as Go build system can't build the `tfhe-rs` library that `fhevm-go` needs. It's therefore necessary that we build it manually as mentioned above, then point to our ready-to-use directory in `go.mod`
{% endhint %}
