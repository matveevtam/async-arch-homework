package mockeventbroker

import (
	"sync"

	"github.com/matveevtam/async-arch-homework/auth-service/internal/usecases/repositories"
)

type MockEventBroker struct {
	mutex            sync.RWMutex
	userAddedEvents  []repositories.UserAddedEvent
	userUpdateEvents []repositories.UserUpdatedEvent
}

func NewMockEventBroker() *MockEventBroker {
	return &MockEventBroker{
		mutex:            sync.RWMutex{},
		userAddedEvents:  make([]repositories.UserAddedEvent, 0),
		userUpdateEvents: make([]repositories.UserUpdatedEvent, 0),
	}
}

func (b *MockEventBroker) SendUserAdded(event repositories.UserAddedEvent) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.userAddedEvents = append(b.userAddedEvents, event)
	return nil
}

func (b *MockEventBroker) SendUserUpdated(event repositories.UserUpdatedEvent) error {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	b.userUpdateEvents = append(b.userUpdateEvents, event)
	return nil
}
