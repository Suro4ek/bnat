// Package bnat holds files embedded into the bnat binary.
package bnat

import _ "embed"

// InstallScript is install.sh, served by the server's release mirror.
//
//go:embed install.sh
var InstallScript string
