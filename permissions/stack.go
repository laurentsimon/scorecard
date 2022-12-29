package permissions

import (
	"bytes"
	"encoding/json"
	"runtime"
)

type Frame struct {
	Function string `json:"function"`
	Pkg      string `json:"package"`
}
type Stack struct {
	DirectPkg string       `json:"direct"`
	CallerPkg string       `json:"caller"`
	ResType   ResourceType `json:"resourceType"`
	ResName   string       `json:"resourceName"`
	Access    Access       `json:"access"`
	Trace     []Frame      `json:"frames"`
	rpcs      []uintptr
}

func (s *Stack) ToJSON() (string, error) {
	frames := runtime.CallersFrames(s.rpcs)
	for {
		curr, more := frames.Next()
		pkg := getPackageName(curr.Function)
		s.Trace = append(s.Trace, Frame{
			Function: curr.Function,
			Pkg:      pkg,
		})
		if !more {
			break
		}
	}

	var output string
	buf := bytes.NewBufferString(output)
	encoder := json.NewEncoder(buf)
	if err := encoder.Encode(*s); err != nil {
		return "", err
	}
	return buf.String(), nil
}
