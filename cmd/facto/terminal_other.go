//go:build !linux && !darwin && !windows

package main

import (
	"errors"
	"os"
)

// errNoEchoUnsupported reports a platform without a no-echo read.
var errNoEchoUnsupported = errors.New("no-echo terminal input is not supported on this platform")

// echoOff is not available on this platform: login prompts fail closed
// rather than echo a code.
func echoOff(*os.File) (func(), error) { return nil, errNoEchoUnsupported }
