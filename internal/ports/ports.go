// Package ports define los puertos (interfaces) entre la aplicación y los
// adaptadores de entrada.
package ports

// ConfigSource da acceso de solo lectura a un árbol de configuración. Las rutas
// son relativas a la raíz, con separador "/", sin "..".
type ConfigSource interface {
	// ReadFile devuelve el contenido; error que satisface errors.Is(err, fs.ErrNotExist) si no existe.
	ReadFile(path string) ([]byte, error)
	// Glob devuelve las rutas que coinciden con el patrón (sintaxis path.Match), ordenadas.
	Glob(pattern string) ([]string, error)
}

// VersionSource provee los textos de versión. ok=false si no se proveyó.
type VersionSource interface {
	Installed() (text string, ok bool, err error)
	Running() (text string, ok bool, err error)
}
