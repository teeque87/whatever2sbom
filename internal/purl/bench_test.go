package purl

import "testing"

func BenchmarkQuoteVersion_Simple(b *testing.B) {
	// No characters need encoding — fast path.
	for i := 0; i < b.N; i++ {
		_ = QuoteVersion("1.2.3-1")
	}
}

func BenchmarkQuoteVersion_Encoded(b *testing.B) {
	// "+" forces percent-encoding — exercises the slow path.
	for i := 0; i < b.N; i++ {
		_ = QuoteVersion("2.34+dfsg-1ubuntu1.2")
	}
}

func BenchmarkDeb(b *testing.B) {
	// Version with "+" forces percent-encoding — the slow path.
	for i := 0; i < b.N; i++ {
		_ = Deb("debian", "libfoo", "2.34+dfsg-1ubuntu1.2", "amd64", "bookworm")
	}
}
