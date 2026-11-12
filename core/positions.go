package core

import (
	"os"
	"regexp"
	"strings"

	"github.com/rhysd/actionlint"
)

// the header of a block scalar at the end of a line: "run: |", "- run: |-", "script: >+ # comment"
var blockHeaderRegexp = regexp.MustCompile(`(?::|-)\s+([|>][-+0-9]*)\s*(?:#.*)?$`)

// FixPositions corrects the positions of the errors with the source of the files.
//
// The rules only know the AST, where the indentation of a block scalar ("run: |", "prompt: |") is lost: they know the
// line of a problem in such a string but not its column. A rule reports the column of these lines as the negative
// of its column counted from the first non-blank character of the line (see rules.posInString), and the real column
// is computed here. This is also done for:
//   - a block scalar with a single line and no trailing newline ("run: |-"): it looks like a value on the line of the key
//   - a column after the end of the line, that would hide the snippet of the error
func FixPositions(errs []*actionlint.Error) {
	FixPositionsWith(errs, os.ReadFile)
}

// FixPositionsWith is FixPositions with a custom way to read the files.
func FixPositionsWith(errs []*actionlint.Error, readFile func(string) ([]byte, error)) {
	lines := map[string][]string{} // by file, nil if it can't be read

	for _, e := range errs {
		src, ok := lines[e.Filepath]
		if !ok {
			if data, err := readFile(e.Filepath); err == nil {
				src = strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
			}

			lines[e.Filepath] = src
		}

		fixPosition(e, src)
	}
}

func fixPosition(e *actionlint.Error, src []string) {
	if e.Line < 1 || e.Line > len(src) {
		return
	}

	line := src[e.Line-1]

	// the value of the key of this line is a block scalar and the error is in it, but on the line of the key
	// (the value has a single line and no trailing newline: "run: |-")
	if h := blockHeaderRegexp.FindStringSubmatchIndex(line); h != nil && e.Column > h[2] {
		fixInBlock(e, src, e.Line-1, line[h[2]], e.Column-(h[2]+1))

		return
	}

	// the first line of a folded block scalar: the column is the offset in the folded value
	if e.Column < 0 && e.Line >= 2 {
		if h := blockHeaderRegexp.FindStringSubmatchIndex(src[e.Line-2]); h != nil && src[e.Line-2][h[2]] == '>' {
			fixInBlock(e, src, e.Line-2, '>', -e.Column-1)

			return
		}
	}

	switch {
	case e.Column < 0:
		e.Column = indentOf(line) - e.Column
	case e.Column-1 > len(line):
		// point at the text of the line
		e.Column = indentOf(line) + 1
	}
}

// fixInBlock moves the error to the line of the block scalar that has the byte offset of the value.
// header is the index of the line of the key, style the "|" or ">" of the scalar.
func fixInBlock(e *actionlint.Error, src []string, header int, style byte, offset int) {
	if header+1 >= len(src) {
		return
	}

	base := indentOf(src[header+1]) // the indentation of the first line is the one of the block

	for i := header + 1; i < len(src); i++ {
		line := src[i]
		if strings.TrimSpace(line) != "" && indentOf(line) < base {
			return // the end of the block
		}

		text := strings.TrimPrefix(line, line[:min(base, indentOf(line))])
		if style == '|' || offset <= len(text) {
			e.Line = i + 1
			e.Column = base + offset + 1

			return
		}

		// a folded block joins its lines with a space
		offset -= len(text) + 1
	}
}

func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}
