package bubbletea

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRingBuffer_Basic(t *testing.T) {
	rb := NewRingBuffer[int](3)

	// Test empty buffer
	assert.Equal(t, 0, rb.Len())
	assert.Empty(t, rb.Items())

	// Add items within capacity
	rb.Add(1)
	assert.Equal(t, 1, rb.Len())
	assert.Equal(t, []int{1}, rb.Items())

	rb.Add(2)
	assert.Equal(t, 2, rb.Len())
	assert.Equal(t, []int{1, 2}, rb.Items())

	rb.Add(3)
	assert.Equal(t, 3, rb.Len())
	assert.Equal(t, []int{1, 2, 3}, rb.Items())

	// Add item exceeding capacity
	rb.Add(4)
	assert.Equal(t, 3, rb.Len())
	assert.Equal(t, []int{2, 3, 4}, rb.Items())

	// Add more items
	rb.Add(5)
	rb.Add(6)
	assert.Equal(t, 3, rb.Len())
	assert.Equal(t, []int{4, 5, 6}, rb.Items())
}

func TestRingBuffer_Clear(t *testing.T) {
	rb := NewRingBuffer[string](5)

	// Add items
	rb.Add("a")
	rb.Add("b")
	rb.Add("c")
	assert.Equal(t, 3, rb.Len())

	// Clear
	rb.Clear()
	assert.Equal(t, 0, rb.Len())
	assert.Empty(t, rb.Items())

	// Add after clear
	rb.Add("d")
	assert.Equal(t, 1, rb.Len())
	assert.Equal(t, []string{"d"}, rb.Items())
}

func TestRingBuffer_Latest(t *testing.T) {
	rb := NewRingBuffer[int](3)

	// Empty buffer
	latest, ok := rb.Latest()
	assert.False(t, ok)
	assert.Equal(t, 0, latest)

	// Add items
	rb.Add(1)
	latest, ok = rb.Latest()
	assert.True(t, ok)
	assert.Equal(t, 1, latest)

	rb.Add(2)
	rb.Add(3)
	latest, ok = rb.Latest()
	assert.True(t, ok)
	assert.Equal(t, 3, latest)

	// Exceed capacity
	rb.Add(4)
	rb.Add(5)
	latest, ok = rb.Latest()
	assert.True(t, ok)
	assert.Equal(t, 5, latest)
}

func TestRingBuffer_ZeroCapacity(t *testing.T) {
	// Zero capacity should default to 1
	rb := NewRingBuffer[int](0)

	rb.Add(1)
	assert.Equal(t, 1, rb.Len())
	assert.Equal(t, []int{1}, rb.Items())

	rb.Add(2)
	assert.Equal(t, 1, rb.Len())
	assert.Equal(t, []int{2}, rb.Items())
}

func TestRingBuffer_Structs(t *testing.T) {
	type TestStruct struct {
		Name string
		ID   int
	}

	rb := NewRingBuffer[TestStruct](2)

	// Add structs
	rb.Add(TestStruct{ID: 1, Name: "First"})
	rb.Add(TestStruct{ID: 2, Name: "Second"})
	rb.Add(TestStruct{ID: 3, Name: "Third"})

	items := rb.Items()
	assert.Len(t, items, 2)
	assert.Equal(t, TestStruct{ID: 2, Name: "Second"}, items[0])
	assert.Equal(t, TestStruct{ID: 3, Name: "Third"}, items[1])
}

func TestRingBuffer_LargeCapacity(t *testing.T) {
	rb := NewRingBuffer[int](1000)

	// Add many items
	for i := 0; i < 500; i++ {
		rb.Add(i)
	}
	assert.Equal(t, 500, rb.Len())

	// Verify order
	items := rb.Items()
	for i := 0; i < 500; i++ {
		assert.Equal(t, i, items[i])
	}

	// Exceed capacity
	for i := 500; i < 1500; i++ {
		rb.Add(i)
	}
	assert.Equal(t, 1000, rb.Len())

	// Verify only last 1000 items remain
	items = rb.Items()
	for i := 0; i < 1000; i++ {
		assert.Equal(t, i+500, items[i])
	}
}
