package knowledge

import (
	"context"
)

// MockBase implements Base for testing.
type MockBase struct {
	GetFunc    func(ctx context.Context, id string) (*Entry, error)
	SearchFunc func(ctx context.Context, query string, limit int) ([]*Entry, error)
	StoreFunc  func(ctx context.Context, entry *Entry) error
	UpdateFunc func(ctx context.Context, id string, entry *Entry) error
	DeleteFunc func(ctx context.Context, id string) error
	IndexFunc  func(ctx context.Context) error
}

// Get implements Base interface.
func (m *MockBase) Get(ctx context.Context, id string) (*Entry, error) {
	if m.GetFunc != nil {
		return m.GetFunc(ctx, id)
	}
	return nil, &EntryNotFoundError{ID: id}
}

// Search implements Base interface.
func (m *MockBase) Search(ctx context.Context, query string, limit int) ([]*Entry, error) {
	if m.SearchFunc != nil {
		return m.SearchFunc(ctx, query, limit)
	}
	return []*Entry{}, nil
}

// Store implements Base interface.
func (m *MockBase) Store(ctx context.Context, entry *Entry) error {
	if m.StoreFunc != nil {
		return m.StoreFunc(ctx, entry)
	}
	return nil
}

// Update implements Base interface.
func (m *MockBase) Update(ctx context.Context, id string, entry *Entry) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(ctx, id, entry)
	}
	return nil
}

// Delete implements Base interface.
func (m *MockBase) Delete(ctx context.Context, id string) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, id)
	}
	return nil
}

// Index implements Base interface.
func (m *MockBase) Index(ctx context.Context) error {
	if m.IndexFunc != nil {
		return m.IndexFunc(ctx)
	}
	return nil
}

// NewMockBase creates a new mock knowledge base for testing.
func NewMockBase() *MockBase {
	return &MockBase{}
}
