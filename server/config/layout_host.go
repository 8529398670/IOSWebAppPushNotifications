//go:build !container

package config

// pinned is empty outside the container image: every path and the listen
// address come from config.yaml. See layout_container.go for the other side.
var pinned = layout{}
