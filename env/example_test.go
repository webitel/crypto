package env_test

import (
	"fmt"
	"os"

	"github.com/webitel/crypto/env"
)

// Example reads WBTL_APP_* configuration through a nested namespace: the code names only
// the leaf keys (NAME, DEBUG) while the WBTL_APP_ prefix is carried by the reader.
func Example() {

	os.Setenv("WBTL_APP_NAME", "webitel")
	os.Setenv("WBTL_APP_DEBUG", "true")

	app := env.Environment("APP") // reads WBTL_APP_*

	var name string
	var debug bool
	app.Apply(
		env.String("NAME", func(v string, set bool) { name = v }),
		env.Bool("DEBUG", func(v bool, err error) { debug = v }),
	)

	fmt.Printf("name=%s debug=%v\n", name, debug)
	// Output: name=webitel debug=true
}
