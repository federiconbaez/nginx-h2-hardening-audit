package porttest

import (
	"testing"

	"github.com/federiconbaez/nginx-h2-hardening-audit/internal/ports"
)

func TestMemSourceContract(t *testing.T) {
	ConfigSourceContract(t, func(_ *testing.T, files map[string]string) ports.ConfigSource {
		return MemSource(files)
	})
}
