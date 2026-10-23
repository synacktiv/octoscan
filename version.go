package main

import "runtime/debug"

// version is the release version. The release workflow injects it with
// -ldflags "-X main.version=vX.Y.Z"; a plain `go build` leaves it at "dev".
var version = "dev"

// versionString returns the version this binary was built as. A build that
// carries the module version in its build info (a `go install <module>@<version>`
// build) reports that, so the binary never claims a version older than itself.
func versionString() string {
	if version != "dev" {
		return version
	}

	if info, ok := debug.ReadBuildInfo(); ok &&
		info.Main.Version != "" &&
		info.Main.Version != "(devel)" {
		return info.Main.Version
	}

	return version
}
