// Package webui optionally embeds the built React SPA into the binary.
//
// By default FS is nil and the server serves the SPA from disk
// (PATD_STATIC_DIR). For a single-binary release, build the frontend, copy it
// next to this package, and build with the `embed` tag:
//
//	cd web && npm ci --ignore-scripts && npm run build
//	rm -rf internal/webui/dist && cp -r web/dist internal/webui/dist
//	go build -tags embed -o patd ./cmd/patd
//
// The default (untagged) build never needs internal/webui/dist, so CI, tests,
// and dev builds work without a frontend build.
package webui

import "io/fs"

// FS is the embedded SPA filesystem, or nil when built without the `embed` tag.
var FS fs.FS
