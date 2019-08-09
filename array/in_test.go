package array

import (
	"fmt"
	"math/rand"
	"testing"
)

type T struct {
	test1 string
	test2 int
}

func ExampleIn_int() {
	a := []int{1, 2, 3, 4}

	fmt.Println(In(2, a))
	// Output:
	// true
}

// Benchmarks
// In
func benchmarkIn(len int, b *testing.B) {
	var o []int

	for i := 0; i < len; i++ {
		o = append(o, rand.Int())
	}

	item := o[rand.Intn(len)]

	for n := 0; n < b.N; n++ {
		In(item, o)
	}
}

func BenchmarkInLen5(b *testing.B)       { benchmarkIn(5, b) }
func BenchmarkInLen100(b *testing.B)     { benchmarkIn(100, b) }
func BenchmarkInLen1000(b *testing.B)    { benchmarkIn(1000, b) }
func BenchmarkInLen1000000(b *testing.B) { benchmarkIn(1000000, b) }

// Tests
func TestIn_notslice(t *testing.T) {
	a := 14

	if In(0, a) {
		t.Fatalf("Should fail")
	}
}

func TestIn_intequal(t *testing.T) {
	a := []int{1, 2, 3, 4}

	if !In(2, a) {
		t.Fatalf("Incorrect answer")
	}
}

func TestIn_intnotequal(t *testing.T) {
	a := []int{1, 2, 3, 4}

	if In(0, a) {
		t.Fatalf("Incorrect answer")
	}
}

func TestIn_stringequal(t *testing.T) {
	a := []string{"dam", "test", "memes"}

	if !In("test", a) {
		t.Fatalf("Incorrect answer")
	}
}

func TestIn_stringnotequal(t *testing.T) {
	a := []string{"test", "memes", "dam"}

	if In("wtf", a) {
		t.Fatalf("Incorrect answer")
	}
}
