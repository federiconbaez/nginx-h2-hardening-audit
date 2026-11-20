package domain

import "strings"

// Directive es una directiva de nginx con su ubicación.
type Directive struct {
	Name  string
	Args  []string
	File  string
	Line  int
	Block []Directive // nil si no tiene bloque
}

// Location devuelve "archivo:línea".
func (d Directive) Location() string { return d.File + ":" + itoa(d.Line) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

const maxConfigBytes = 8 << 20

type token struct {
	text   string
	line   int
	quoted bool
}

// ParseConfig parsea el contenido de un archivo de configuración de nginx. Es
// puro: no resuelve includes (eso lo hace la capa de aplicación).
func ParseConfig(file string, src []byte) ([]Directive, error) {
	if len(src) > maxConfigBytes {
		return nil, &ParseError{File: file, Line: 1, Msg: "file too large"}
	}
	toks, err := tokenize(file, src)
	if err != nil {
		return nil, err
	}
	p := &parser{file: file, toks: toks}
	ds, err := p.block(0)
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.toks) {
		t := p.toks[p.pos]
		return nil, &ParseError{File: file, Line: t.line, Msg: "unexpected \"}\""}
	}
	return ds, nil
}

func tokenize(file string, src []byte) ([]token, error) {
	var out []token
	line := 1
	i := 0
	for i < len(src) {
		c := src[i]
		switch {
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r':
			i++
		case c == '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
		case c == ';' || c == '{' || c == '}':
			out = append(out, token{text: string(c), line: line})
			i++
		case c == '"' || c == '\'':
			q := c
			start := line
			i++
			var b strings.Builder
			closed := false
			for i < len(src) {
				ch := src[i]
				if ch == '\\' && i+1 < len(src) {
					if src[i+1] == '\n' {
						line++
					}
					b.WriteByte(src[i+1])
					i += 2
					continue
				}
				if ch == q {
					closed = true
					i++
					break
				}
				if ch == '\n' {
					line++
				}
				b.WriteByte(ch)
				i++
			}
			if !closed {
				return nil, &ParseError{File: file, Line: start, Msg: "unterminated quoted string"}
			}
			out = append(out, token{text: b.String(), line: start, quoted: true})
		default:
			start := i
			for i < len(src) {
				ch := src[i]
				if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == ';' || ch == '{' || ch == '}' {
					break
				}
				if ch == '\\' && i+1 < len(src) {
					i += 2
					continue
				}
				i++
			}
			out = append(out, token{text: string(src[start:i]), line: line})
		}
	}
	return out, nil
}

type parser struct {
	file string
	toks []token
	pos  int
}

const maxNesting = 64

func (p *parser) block(depth int) ([]Directive, error) {
	if depth > maxNesting {
		line := 1
		if p.pos < len(p.toks) {
			line = p.toks[p.pos].line
		}
		return nil, &ParseError{File: p.file, Line: line, Msg: "blocks nested too deeply"}
	}
	var out []Directive
	for p.pos < len(p.toks) {
		t := p.toks[p.pos]
		if !t.quoted && t.text == "}" {
			if depth == 0 {
				return nil, &ParseError{File: p.file, Line: t.line, Msg: "unexpected \"}\""}
			}
			return out, nil
		}
		if !t.quoted && (t.text == ";" || t.text == "{") {
			return nil, &ParseError{File: p.file, Line: t.line, Msg: "unexpected \"" + t.text + "\""}
		}
		d := Directive{Name: t.text, File: p.file, Line: t.line}
		p.pos++
		terminated := false
		for p.pos < len(p.toks) {
			a := p.toks[p.pos]
			if !a.quoted && a.text == ";" {
				p.pos++
				terminated = true
				break
			}
			if !a.quoted && a.text == "{" {
				p.pos++
				inner, err := p.block(depth + 1)
				if err != nil {
					return nil, err
				}
				if p.pos >= len(p.toks) {
					return nil, &ParseError{File: p.file, Line: a.line, Msg: "unexpected end of file, expecting \"}\""}
				}
				p.pos++ // consume "}"
				if inner == nil {
					inner = []Directive{}
				}
				d.Block = inner
				terminated = true
				break
			}
			if !a.quoted && a.text == "}" {
				return nil, &ParseError{File: p.file, Line: a.line, Msg: "unexpected \"}\""}
			}
			d.Args = append(d.Args, a.text)
			p.pos++
		}
		if !terminated {
			return nil, &ParseError{File: p.file, Line: d.Line, Msg: "unexpected end of file, expecting \";\" or \"}\""}
		}
		out = append(out, d)
	}
	if depth > 0 {
		return nil, &ParseError{File: p.file, Line: lastLine(p.toks), Msg: "unexpected end of file, expecting \"}\""}
	}
	return out, nil
}

func lastLine(t []token) int {
	if len(t) == 0 {
		return 1
	}
	return t[len(t)-1].line
}

// Walk recorre las directivas en profundidad (pre-orden) con su contexto
// (nombres de los bloques padre).
func Walk(ds []Directive, fn func(d Directive, ctx []string)) {
	walk(ds, nil, fn)
}

func walk(ds []Directive, ctx []string, fn func(Directive, []string)) {
	for _, d := range ds {
		fn(d, ctx)
		if d.Block != nil {
			walk(d.Block, append(ctx[:len(ctx):len(ctx)], d.Name), fn)
		}
	}
}
