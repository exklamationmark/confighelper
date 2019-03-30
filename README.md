# confighelpers

Package confighelpers helps you define and validate configuration files
more easily.

It's designed to provide dev an easy way to create and validate YAML
configuration files, in order to make development/operation more convenient.

Specifically, the packages try to help you with these scenarios:

## unvalidated config

After hours of troubleshooting a failed deployment, you realized the problem
was misconfigured/missing key.

Unlike the standard library's `flag`, which provide default values and
type-check, when we use YAML config files, we are back to the land of
text and zero-values.

If would be convenient if the config struct(s) we unmarshal comes with a
`Check() error` function. The library provide you exactly that.

## power-on self-test

Sometimes you would need to go further than validating that values in the
config YAML is correct. For example, you might need to check if dependencies
(e.g., DB, external services, etc) are up before starting your own app.

The library also provide common functions for that, too
(e.g., `Ping()` over mutual TLS).
