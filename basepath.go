package lib

import (
	"strings"

	wl_fs "github.com/wsva/lib_go/fs"
)

func ReplaceBasePath(dir string) string {
	basepath, _ := wl_fs.GetExecutableFullpath()
	return strings.ReplaceAll(dir, "{BasePath}", basepath)
}
