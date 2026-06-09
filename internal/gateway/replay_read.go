package gateway

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// ReplayReader is the read side of a ReplayStore: it fetches a finished
// session's recording for the replay-retrieval API. FilesystemReplayStore,
// S3ReplayStore, and MemoryReplayStore all implement it, anchored on the same
// canonical ReplayKey the recorder wrote under, so a session recorded by the
// gateway can be replayed by the control plane regardless of the backend.
type ReplayReader interface {
	// GetReplay returns the recording for sessionID. The caller must Close the
	// reader. A missing recording is reported as os.ErrNotExist so the HTTP
	// edge can map it to 404.
	GetReplay(ctx context.Context, sessionID string) (io.ReadCloser, error)
}

// ReplayFrame is one decoded frame of a recorded session: a direction, the
// capture time, and the payload bytes. The replay API marshals these to JSON
// (Payload base64-encodes automatically) so a UI can colour the transcript by
// direction and scrub on the timeline.
type ReplayFrame struct {
	// Direction is "input" (operator→target), "output" (target→operator), or
	// "control" (proxy-injected annotation).
	Direction string `json:"direction"`
	// At is the capture timestamp of the frame.
	At time.Time `json:"at"`
	// Payload is the raw bytes recorded in this frame.
	Payload []byte `json:"payload"`
}

// directionLabel maps the on-wire direction byte to its API label. An unknown
// byte is surfaced verbatim rather than hidden, so a corrupt/foreign recording
// is visible instead of silently mislabelled.
func directionLabel(d Direction) string {
	switch d {
	case DirInput:
		return "input"
	case DirOutput:
		return "output"
	case DirControl:
		return "control"
	default:
		return fmt.Sprintf("unknown(%#x)", byte(d))
	}
}

// maxReplayFramePayload bounds a single decoded frame at 32 MiB. The recorder
// never writes a frame larger than its read buffer, so any length prefix beyond
// this is a sign of a corrupt or hostile recording; rejecting it stops a
// crafted length header from forcing a multi-gigabyte allocation when the API
// parses a recording.
const maxReplayFramePayload = 32 << 20

// ParseReplay decodes a framed recording into ordered frames. Frames are
// already timestamp-ordered as written, so the slice preserves capture order.
// A truncated trailing frame (the recording was cut off mid-write) returns the
// frames decoded so far with io.ErrUnexpectedEOF, so a partial recording is
// still replayable up to the cut.
func ParseReplay(r io.Reader) ([]ReplayFrame, error) {
	var frames []ReplayFrame
	var hdr [frameHeaderLen]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			if err == io.EOF {
				return frames, nil
			}
			if err == io.ErrUnexpectedEOF {
				return frames, io.ErrUnexpectedEOF
			}
			return frames, fmt.Errorf("gateway: ParseReplay: read header: %w", err)
		}
		dir := Direction(hdr[0])
		nanos := int64(binary.BigEndian.Uint64(hdr[1:9]))
		length := binary.BigEndian.Uint32(hdr[9:13])
		if length > maxReplayFramePayload {
			return frames, fmt.Errorf("gateway: ParseReplay: frame length %d exceeds cap %d", length, maxReplayFramePayload)
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				return frames, io.ErrUnexpectedEOF
			}
			return frames, fmt.Errorf("gateway: ParseReplay: read payload: %w", err)
		}
		frames = append(frames, ReplayFrame{
			Direction: directionLabel(dir),
			At:        time.Unix(0, nanos).UTC(),
			Payload:   payload,
		})
	}
}
