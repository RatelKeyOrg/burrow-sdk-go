package burrow

import (
	"runtime/debug"
	"strings"
)

// modulePath is this module's import path, as go.mod declares it.
const modulePath = "github.com/RatelKeyOrg/burrow-sdk-go"

// SDKVersion is the release of this SDK the program was built with ("1.2.0"), as Go's module system recorded it, or
// "dev" when it was built from source that isn't a published release.
var SDKVersion = moduleVersion()

// DefaultClientTag is the Ratel-Client tag sent with each request unless WithClientTag names another. The Burrow's audit
// trail shows it against each read, as "Go SDK" and the version.
var DefaultClientTag = "ratel-sdk-go/" + SDKVersion

// moduleVersion reads this module's version from the program's build information. A release is fetched by its tag, so
// the tag is the version and no file in the module repeats it.
func moduleVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "dev"
	}
	return versionIn(info)
}

func versionIn(info *debug.BuildInfo) string {
	version := ""
	if info.Main.Path == modulePath {
		version = info.Main.Version
	}
	for _, dep := range info.Deps {
		if dep.Path != modulePath {
			continue
		}
		version = dep.Version
		if dep.Replace != nil {
			version = dep.Replace.Version
		}
	}
	if version == "" || version == "(devel)" {
		return "dev"
	}
	return strings.TrimPrefix(version, "v")
}
