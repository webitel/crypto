// Package jsonc reads JSONC — JSON with comments and trailing commas — and
// presents it as plain JSON. It is a thin streaming layer over encoding/json with
// no external dependencies, intended for human-edited configuration files where
// comments (to document and to quickly disable blocks) and forgiving trailing
// commas matter.
//
// The core is Reader, an io.Reader that wraps a JSONC source and yields clean
// JSON. The transform is length-preserving: each stripped comment byte and each
// dropped trailing comma is replaced by a space (newlines inside comments are
// kept), so byte offsets and line numbers survive into encoding/json's error
// messages. Comment markers and commas inside string literals are left untouched.
//
// Supported extensions over strict JSON:
//   - // line comments and /* block comments */
//   - a single trailing comma before } or ]
package jsonc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
)

// Reader wraps a JSONC source and reads it back as plain JSON. It is not safe for
// concurrent use.
type Reader struct {
	br  *bufio.Reader
	out bytes.Buffer // transformed bytes awaiting Read
	err error        // sticky source error, surfaced once out is drained

	inString bool
	escaped  bool

	// A comma is held until the next significant byte decides its fate: dropped
	// (replaced by a space) before } or ], kept otherwise. Whitespace and comment
	// bytes seen meanwhile are buffered in pendingWS so they emit in order.
	pendingComma bool
	pendingWS    []byte
}

// NewReader returns a Reader that converts the JSONC in r to JSON.
func NewReader(r io.Reader) *Reader {
	return &Reader{br: bufio.NewReader(r)}
}

// Read implements io.Reader, emitting the JSON translation of the source.
func (r *Reader) Read(p []byte) (int, error) {
	for r.out.Len() == 0 && r.err == nil {
		r.pump()
	}
	if r.out.Len() > 0 {
		return r.out.Read(p)
	}
	return 0, r.err
}

// pump consumes one logical unit from the source and advances internal state,
// writing any resolved output to out. It sets r.err when the source is exhausted.
func (r *Reader) pump() {
	c, err := r.br.ReadByte()
	if err != nil {
		if r.pendingComma { // trailing comma at EOF: keep it, let json report it
			r.flushComma()
		}
		r.err = err
		return
	}

	if r.inString {
		r.out.WriteByte(c)
		switch {
		case r.escaped:
			r.escaped = false
		case c == '\\':
			r.escaped = true
		case c == '"':
			r.inString = false
		}
		return
	}

	switch c {
	case '"':
		r.resolveComma(false)
		r.out.WriteByte(c)
		r.inString = true
	case ',':
		r.resolveComma(false) // flush a preceding comma (malformed, but lossless)
		r.pendingComma = true
	case ' ', '\t', '\r', '\n':
		r.emitWS(c)
	case '/':
		r.slashOrComment()
	case '}', ']':
		r.resolveComma(true)
		r.out.WriteByte(c)
	default:
		r.resolveComma(false)
		r.out.WriteByte(c)
	}
}

// slashOrComment handles a '/': a // or /* */ comment (replaced by spaces), or an
// otherwise-stray slash passed through for json to reject.
func (r *Reader) slashOrComment() {
	next, _ := r.br.Peek(1)
	switch {
	case len(next) == 1 && next[0] == '/':
		r.br.ReadByte()
		r.emitWS(' ')
		r.emitWS(' ')
		for {
			b, err := r.br.ReadByte()
			if err != nil {
				return
			}
			if b == '\n' {
				r.emitWS('\n')
				return
			}
			r.emitWS(' ')
		}
	case len(next) == 1 && next[0] == '*':
		r.br.ReadByte()
		r.emitWS(' ')
		r.emitWS(' ')
		for {
			b, err := r.br.ReadByte()
			if err != nil {
				return
			}
			if b == '\n' {
				r.emitWS('\n')
				continue
			}
			if b == '*' {
				if p, _ := r.br.Peek(1); len(p) == 1 && p[0] == '/' {
					r.br.ReadByte()
					r.emitWS(' ')
					r.emitWS(' ')
					return
				}
			}
			r.emitWS(' ')
		}
	default:
		r.resolveComma(false)
		r.out.WriteByte('/')
	}
}

// resolveComma settles a held comma now that the next significant byte is known:
// before a closing bracket it is dropped (→ space), otherwise kept. Buffered
// whitespace always follows.
func (r *Reader) resolveComma(beforeClose bool) {
	if !r.pendingComma {
		return
	}
	if beforeClose {
		r.out.WriteByte(' ')
	} else {
		r.out.WriteByte(',')
	}
	r.out.Write(r.pendingWS)
	r.pendingComma = false
	r.pendingWS = r.pendingWS[:0]
}

func (r *Reader) flushComma() {
	r.out.WriteByte(',')
	r.out.Write(r.pendingWS)
	r.pendingComma = false
	r.pendingWS = r.pendingWS[:0]
}

// emitWS writes a whitespace byte, buffering it after a held comma so ordering is
// preserved when the comma is later kept.
func (r *Reader) emitWS(c byte) {
	if r.pendingComma {
		r.pendingWS = append(r.pendingWS, c)
		return
	}
	r.out.WriteByte(c)
}

// NewDecoder returns a *json.Decoder reading the JSON translation of r. Configure
// it as usual, e.g. dec.DisallowUnknownFields().
func NewDecoder(r io.Reader) *json.Decoder {
	return json.NewDecoder(NewReader(r))
}

// Unmarshal parses JSONC data into v, like json.Unmarshal but tolerating comments
// and trailing commas.
func Unmarshal(data []byte, v any) error {
	return json.Unmarshal(ToJSON(data), v)
}

// ToJSON returns the plain-JSON translation of JSONC data. On a malformed source
// it returns the best-effort partial translation (json.Unmarshal then reports the
// error); ToJSON itself never fails because the in-memory transform cannot.
func ToJSON(data []byte) []byte {
	var buf bytes.Buffer
	// ReadFrom drains a *Reader fully; the only error it could surface is the
	// source's io.EOF, which ReadFrom treats as success.
	_, _ = buf.ReadFrom(NewReader(bytes.NewReader(data)))
	return buf.Bytes()
}
