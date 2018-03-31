package util

import (
	"os"
	"runtime"
	"strings"
)

const (
	//window os
	OS_TYPE_WINDOWS = "windows"
	//mac os
	OS_TYPE_DARWIN = "darwin"
	//GNU/linux os
	OS_TYPE_LINUX = "linux"
	//freebsd os
	OS_TYPE_FREEBSD = "freebsd"
)

func GetProjectDir() string {
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return dir
}

//FormatFilePath 根据系统类型格式化文件路径
func FormatFilePath(filepath string) string {
	switch runtime.GOOS {
	case OS_TYPE_WINDOWS:
		return strings.Replace(filepath, "/", "\\", -1)
	default:
		return filepath
	}
}
