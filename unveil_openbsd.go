// Copyright (c) 2023 Tim van der Molen <tim@kariliq.nl>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

package openbsd

import (
	"errors"
	"fmt"
	"io/fs"

	"golang.org/x/sys/unix"
)

func Unveil(path, permissions string) error {
	if err := unix.Unveil(path, permissions); err != nil {
		return fmt.Errorf("unveil: %s: %w", path, err)
	}
	return nil
}

func UnveilBlock() error {
	if err := unix.UnveilBlock(); err != nil {
		return fmt.Errorf("unveil: %w", err)
	}
	return nil
}

func UnveilMime() error {
	paths := []string{
		"/etc/apache/mime.types",
		"/etc/apache2/mime.types",
		"/etc/httpd/conf/mime.types",
		"/etc/mime.types",
		"/usr/local/share/mime/globs2",
		"/usr/share/mime/globs2",
		"/usr/share/misc/mime.types",
	}
	return unveilPaths(paths)
}

func UnveilNet() error {
	paths := []string{
		"/etc/hosts",
		"/etc/protocols",
		"/etc/resolv.conf",
		"/etc/services",
	}
	return unveilPaths(paths)
}

func UnveilTime() error {
	paths := []string{
		"/etc/localtime",
		"/usr/share/zoneinfo",
	}
	return unveilPaths(paths)
}

func UnveilUser() error {
	paths := []string{
		"/etc/group",
		"/etc/passwd",
	}
	return unveilPaths(paths)
}

func UnveilX509() error {
	paths := []string{
		"/etc/ssl/cert.pem",
	}
	return unveilPaths(paths)
}

func unveilPaths(paths []string) error {
	for i := range paths {
		err := Unveil(paths[i], "r")
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}
