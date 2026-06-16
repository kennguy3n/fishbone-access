package gateway

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// This file adds the READ-SIDE helpers that turn a stored recording into
// searchable, verifiable, replayable data for the forensic store
// (internal/services/recordings + the replay API). It is additive: it never
// changes how recorder.go writes frames, only how a finished recording is
// decoded, integrity-checked, and mined for full-text indexing.

// DecodedRecording is the full result of decoding a stored recording: the
// time-ordered frames the replay player renders, the integrity facts the UI
// surfaces as a tamper-evidence badge (the SHA-256 over the exact stored bytes
// and whether it matched the digest the gateway anchored in the audit chain),
// and whether the trailing frame was cut off by the recorder's size cap.
type DecodedRecording struct {
	// Frames are the decoded frames in capture order (the recorder writes them
	// in time order, so no re-sort is needed).
	Frames []ReplayFrame
	// Bytes is the exact number of stored bytes that were hashed/decoded.
	Bytes int64
	// SHA256 is the hex SHA-256 computed over the exact stored bytes — the value
	// to compare against the digest anchored in the audit chain.
	SHA256 string
	// SHA256Verified reports whether SHA256 matched the expected digest the
	// caller passed (false when no expected digest was supplied, or it differed).
	SHA256Verified bool
	// Truncated reports the recording was cut off mid-frame (recorder size cap
	// or an interrupted flush). The frames decoded before the cut are still
	// returned and replayable.
	Truncated bool
}

// maxDecodeBytes bounds how many bytes DecodeAndVerify will buffer for a single
// recording. The recorder enforces its own capture cap, so a stored artifact
// larger than this is corrupt or hostile; rejecting it stops a crafted blob
// from forcing an unbounded allocation when the API decodes it. 256 MiB is well
// above any legitimate recording yet a hard ceiling on memory per replay
// request.
const maxDecodeBytes = 256 << 20

// ErrRecordingTooLarge is returned when a stored recording exceeds
// maxDecodeBytes — a corruption/abuse guard, not an expected condition.
var ErrRecordingTooLarge = errors.New("gateway: recording exceeds maximum decodable size")

// DecodeAndVerify reads a complete stored recording, computes its SHA-256 over
// the exact bytes read, decodes the frames, and reports whether the digest
// matches expectedSHA (the value the gateway anchored in the audit chain). A
// recording cut off mid-frame is NOT an error: the frames decoded before the
// cut are returned with Truncated=true, so a partial recording stays
// replayable up to the cut (matching ParseReplay's contract).
//
// expectedSHA may be empty (the caller has no anchored digest to compare): then
// SHA256 is still computed and returned, but SHA256Verified is false. The
// comparison is case-insensitive on the hex digest.
func DecodeAndVerify(r io.Reader, expectedSHA string) (DecodedRecording, error) {
	if r == nil {
		return DecodedRecording{}, errors.New("gateway: DecodeAndVerify: nil reader")
	}
	// Bound the read so a corrupt length cannot drive an unbounded buffer. Read
	// one extra byte to detect "exceeded the cap" rather than silently truncate.
	limited := io.LimitReader(r, maxDecodeBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return DecodedRecording{}, err
	}
	if int64(len(raw)) > maxDecodeBytes {
		return DecodedRecording{}, ErrRecordingTooLarge
	}

	sum := sha256.Sum256(raw)
	gotSHA := hex.EncodeToString(sum[:])

	frames, perr := ParseReplay(bytes.NewReader(raw))
	truncated := errors.Is(perr, io.ErrUnexpectedEOF)
	if perr != nil && !truncated {
		// A hard decode error (corrupt header, oversize frame) is real: surface
		// it rather than returning a half-decoded recording as if it were clean.
		return DecodedRecording{}, perr
	}

	out := DecodedRecording{
		Frames:    frames,
		Bytes:     int64(len(raw)),
		SHA256:    gotSHA,
		Truncated: truncated,
	}
	if expectedSHA != "" {
		out.SHA256Verified = strings.EqualFold(gotSHA, strings.TrimSpace(expectedSHA))
	}
	return out, nil
}

// ExtractKeystrokeText reconstructs the operator-issued INPUT text from a
// decoded recording for full-text indexing. It mines only DirInput frames
// (operator→target keystrokes), never DirOutput (which holds the target's
// responses, including secrets and query results that must not be indexed), and
// never DirControl (proxy annotations). The reconstruction:
//
//   - keeps printable text (ASCII printable + any multi-byte UTF-8 rune),
//   - applies backspace/delete (0x08, 0x7f) by dropping the last rune typed,
//     so an operator's corrections do not pollute the index with deleted text,
//   - treats CR/LF as line breaks (so each typed command lands on its own line)
//     and TAB as a single space,
//   - drops ESC / CSI control sequences (arrow keys, cursor moves) so terminal
//     control bytes never reach the search text,
//   - collapses other control bytes.
//
// The result is capped at maxLen bytes (0 = no cap) to bound index-row size for
// a pathological session; the cap is applied on a rune boundary so the text
// stays valid UTF-8. This is a best-effort searchable projection, NOT a faithful
// shell transcript — it exists so "find the session where someone typed
// 'DROP TABLE'" works, complementing the structured pam_session_commands rows.
func ExtractKeystrokeText(frames []ReplayFrame, maxLen int) string {
	var b strings.Builder
	// Track the current line as runes so backspace can pop the last rune.
	var line []rune
	flush := func() {
		if len(line) > 0 {
			b.WriteString(string(line))
			line = line[:0]
		}
		b.WriteByte('\n')
	}
	for _, f := range frames {
		if f.Direction != directionLabel(DirInput) {
			continue
		}
		p := f.Payload
		for i := 0; i < len(p); {
			c := p[i]
			switch {
			case c == 0x1b: // ESC: skip the escape/CSI sequence.
				i = skipEscape(p, i)
				continue
			case c == '\r' || c == '\n':
				flush()
				i++
				// Coalesce a CRLF (or LFCR) pair into a single line break so a
				// terminal's "\r\n" does not emit a blank line in the indexed text.
				if i < len(p) && (p[i] == '\r' || p[i] == '\n') && p[i] != c {
					i++
				}
				continue
			case c == '\t':
				line = append(line, ' ')
				i++
				continue
			case c == 0x08 || c == 0x7f: // backspace / delete
				if len(line) > 0 {
					line = line[:len(line)-1]
				}
				i++
				continue
			case c < 0x20: // other control bytes: drop
				i++
				continue
			case c < 0x80: // printable ASCII
				line = append(line, rune(c))
				i++
				continue
			default: // multi-byte UTF-8
				rn, size := utf8.DecodeRune(p[i:])
				if rn == utf8.RuneError && size <= 1 {
					i++ // invalid byte: skip
					continue
				}
				line = append(line, rn)
				i += size
			}
		}
	}
	if len(line) > 0 {
		b.WriteString(string(line))
	}
	out := strings.TrimSpace(b.String())
	if maxLen > 0 && len(out) > maxLen {
		out = truncateOnRune(out, maxLen)
	}
	return out
}

// skipEscape returns the index just past an ANSI escape sequence that begins at
// p[i] (which must be ESC). A CSI sequence (ESC '[') runs until a final byte in
// 0x40–0x7e; any other escape is treated as a two-byte sequence (ESC + one
// byte). When the sequence runs off the end of the buffer, the end index is
// returned so the caller stops cleanly.
func skipEscape(p []byte, i int) int {
	i++ // consume ESC
	if i >= len(p) {
		return i
	}
	if p[i] == '[' { // CSI
		i++
		for i < len(p) {
			if p[i] >= 0x40 && p[i] <= 0x7e {
				return i + 1
			}
			i++
		}
		return i
	}
	// Non-CSI escape: consume the single following byte.
	return i + 1
}

// truncateOnRune cuts s to at most maxLen bytes without splitting a UTF-8 rune.
func truncateOnRune(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	cut := maxLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
