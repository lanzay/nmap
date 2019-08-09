package array

import (
	"fmt"
	"math/rand"
	"testing"
)

// Examples
func ExampleIntersection() {
	a := []int{1, 2, 3}
	b := []int{2, 3, 4}

	intersections, ok := Intersection(a, b).([]int)
	if !ok {
		fmt.Println("Error unwrapping")
	}
	fmt.Println(intersections)
	// Output:
	// [2 3]
}

func ExampleExcept_a() {
	a := []int{1, 2, 5}
	b := []int{2, 3, 4}

	except, ok := Except(a, b).([]int)
	if !ok {
		fmt.Println("Error unwrapping")
	}
	fmt.Println(except)
	// Output:
	// [1 5]
}

func ExampleExcept_b() {
	a := []int{1, 2, 5}
	b := []int{2, 3, 4}

	except, ok := Except(b, a).([]int)
	if !ok {
		fmt.Println("Error unwrapping")
	}
	fmt.Println(except)
	// Output:
	// [3 4]
}

func ExampleExcept_string() {
	a := []string{"who", "what", "when"}
	b := []string{"when", "where", "why"}

	except, ok := Except(a, b).([]string)
	if !ok {
		fmt.Println("Error unwrapping")
	}
	fmt.Println(except)
	// Output:
	// [who what]
}

// Benchmark
func genTwoIntArr(len int) (a []int, b []int) {
	for i := 0; i < len; i++ {
		a = append(a, rand.Intn(100))
		b = append(b, rand.Intn(100))
	}
	return
}

func benchIntersection(len int, b *testing.B) {
	one, two := genTwoIntArr(len)
	for n := 0; n < b.N; n++ {
		Intersection(one, two)
	}
}

func BenchmarkIntersection100(b *testing.B)    { benchIntersection(100, b) }
func BenchmarkIntersection1000(b *testing.B)   { benchIntersection(1000, b) }
func BenchmarkIntersection10000(b *testing.B)  { benchIntersection(10000, b) }
func BenchmarkIntersection100000(b *testing.B) { benchIntersection(100000, b) }

// Tests
// Intersection

func hasInteger(i int, arr []int) bool {
	for _, item := range arr {
		if item == i {
			return true
		}
	}
	return false
}

func hasString(i string, arr []string) bool {
	for _, item := range arr {
		if item == i {
			return true
		}
	}
	return false
}

func TestIntersection(t *testing.T) {
	a := []int{1, 2, 3}
	b := []int{2, 3, 4}

	intersects := Intersection(a, b).([]int)

	if len(intersects) != 2 {
		fmt.Println(intersects)
		t.Fatal("Result array has incorrect terms")
	}

	if !hasInteger(2, intersects) {
		t.Fatal("Number two not found")
	}

	if !hasInteger(3, intersects) {
		t.Fatal("Number three not found")
	}
}

func TestIntersection_notarr(t *testing.T) {
	a := 14

	_, ok := Intersection(a, a).([]int)
	if ok {
		t.Errorf("Not checking types")
	}
}

// Except
func TestExcept_notarr(t *testing.T) {
	a := 14

	_, ok := Except(a, a).([]int)
	if ok {
		t.Errorf("Not checking types")
	}
}

func TestExcept_int(t *testing.T) {
	a := []int{1, 2, 5}
	b := []int{2, 3, 4}

	except := Except(a, b).([]int)

	if len(except) != 2 {
		t.Fatal("Two items should be returned")
	}

	if !hasInteger(1, except) {
		t.Error("Number 'one' not found")
	}
	if !hasInteger(5, except) {
		t.Error("Value 5 was not found")
	}
}

func TestExcept_string(t *testing.T) {
	a := []string{"who", "what", "when"}
	b := []string{"when", "where", "why"}

	except := Except(a, b).([]string)

	if len(except) != 2 {
		t.Fatal("Two items should be returned")
	}

	if !hasString("who", except) {
		t.Fatal("Value 'who' was not found")
	}

	if !hasString("what", except) {
		t.Fatal("Value 'what' was not found")
	}
}

type Testing struct {
	Value  string
	Value2 int
}

func TestExcept_struct(t *testing.T) {
	a := []Testing{
		Testing{"Hello", 1},
		Testing{"Hello", 2},
	}
	b := []Testing{
		Testing{"Hello", 1},
		Testing{"Hello", 3},
	}

	except := Except(a, b).([]Testing)
	if len(except) != 1 {
		t.Fatal("One item should be returned")
	}

	if except[0].Value != "Hello" || except[0].Value2 != 2 {
		t.Errorf("Got value %v\n", except)
		t.Fatal("Value incorrect")
	}
}
