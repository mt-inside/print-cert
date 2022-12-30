package build

// TODO:
// - const?
// - default "unknown"
// - pass from justfile, melange, etc
// - same to http-log's version
var Version string

func NameAndVersion() string {
	return "print-cert " + Version
}
