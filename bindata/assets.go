package bindata

import "embed"

//go:embed assets/*.yaml
var content embed.FS

func MustAsset(name string) []byte {
	data, err := content.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return data
}
