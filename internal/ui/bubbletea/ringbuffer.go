package bubbletea

// RingBuffer is a generic circular buffer with a fixed capacity.
type RingBuffer[T any] struct {
	items    []T
	head     int
	size     int
	capacity int
}

// NewRingBuffer creates a new ring buffer with the specified capacity.
func NewRingBuffer[T any](capacity int) *RingBuffer[T] {
	if capacity <= 0 {
		capacity = 1
	}
	return &RingBuffer[T]{
		items:    make([]T, 0, capacity),
		head:     0,
		size:     0,
		capacity: capacity,
	}
}

// Add adds an item to the ring buffer.
func (r *RingBuffer[T]) Add(item T) {
	if r.size < r.capacity {
		// Buffer not full yet, just append
		r.items = append(r.items, item)
		r.size++
	} else {
		// Buffer full, overwrite oldest item
		r.items[r.head] = item
		r.head = (r.head + 1) % r.capacity
	}
}

// Items returns all items in the buffer in chronological order.
func (r *RingBuffer[T]) Items() []T {
	if r.size < r.capacity {
		// Buffer not full, return as-is
		return append([]T(nil), r.items...)
	}
	// Buffer full, return items in order
	result := make([]T, r.capacity)
	for i := 0; i < r.capacity; i++ {
		result[i] = r.items[(r.head+i)%r.capacity]
	}
	return result
}

// Len returns the number of items in the buffer.
func (r *RingBuffer[T]) Len() int {
	return r.size
}

// Clear removes all items from the buffer.
func (r *RingBuffer[T]) Clear() {
	r.items = r.items[:0]
	r.head = 0
	r.size = 0
}

// Latest returns the most recently added item, or the zero value if empty.
func (r *RingBuffer[T]) Latest() (T, bool) {
	var zero T
	if r.size == 0 {
		return zero, false
	}
	if r.size < r.capacity {
		return r.items[r.size-1], true
	}
	// Get the item before head (most recent)
	idx := r.head - 1
	if idx < 0 {
		idx = r.capacity - 1
	}
	return r.items[idx], true
}
