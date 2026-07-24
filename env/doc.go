// Package env reads configuration from environment variables: typed values plus a
// namespaced key layout that keeps configuration tidy and free of repeated prefixes.
// It is the base-configuration building block for the SDK's modules.
//
// # Typed values
//
// Values are read through small [Option] constructors — one per type — that look a key
// up and hand the parsed value to a callback. [String] and [Bool] ship today; further
// types (Int, Duration, …) follow the same shape and are added as needed.
//
// # Namespaces
//
// Every key lives under a namespace. [Name] builds a namespaced key by joining segments
// with a single underscore: "APP" under the root "WBTL" is "WBTL_APP", and a "DEBUG"
// lookup there resolves to WBTL_APP_DEBUG. Code names only the leaf key; the namespace is
// carried by the [Options] value, so prefixes are never repeated by hand — that is the
// "clean code" the segmentation buys.
//
// # Usage
//
// The package-level [Getenv], [LookupEnv] and [Environment] operate under the global
// WBTL_ root. [Environment] returns an [Options] nested one or more segments deeper; a
// component builds one reader and reads all its keys through [Options.Apply]:
//
//	app := env.Environment("APP") // reads WBTL_APP_*
//
//	var name string
//	var debug bool
//	app.Apply(
//		env.String("NAME", func(v string, set bool) { name = v }),
//		env.Bool("DEBUG", func(v bool, err error) { debug = v }),
//	)
//
// The WBTL_ root is only the package default. You can always describe an environment for
// a namespace of your own by building an [Options] directly:
//
//	mypkg := env.Options{Namespace: env.Name("MY_PKG")} // reads MY_PKG_*
package env
