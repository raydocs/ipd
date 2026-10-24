// Package web is the static UI. It is embedded so the binary has no asset server.
package web

import "embed"

// FS holds the page and the local WebRTC judge.
//
//go:embed index.html style.css app.js judge.js favicon.svg
var FS embed.FS
