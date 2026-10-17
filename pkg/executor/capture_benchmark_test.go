package executor

import (
	"bytes"
	"context"
	"testing"
)

const benchStreamSize = 10 << 20

var benchLine = append(bytes.Repeat([]byte("x"), 63), '\n')

func BenchmarkCapBufferWrite(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(benchStreamSize)
	for b.Loop() {
		c := newCapBuffer()
		for range benchStreamSize / len(benchLine) {
			c.write(benchLine)
		}
		_ = c.bytes()
	}
}

func BenchmarkChunkWriter(b *testing.B) {
	b.ReportAllocs()
	b.SetBytes(benchStreamSize)
	for b.Loop() {
		cw := newChunkWriter(context.Background(), func(context.Context, string) {})
		for range benchStreamSize / len(benchLine) {
			_, _ = cw.Write(benchLine)
		}
		_ = cw.captured()
	}
}
