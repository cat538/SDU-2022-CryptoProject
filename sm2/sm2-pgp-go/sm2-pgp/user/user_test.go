package user

import (
	"fmt"
	"testing"
)

func TestUser(t *testing.T) {
	Alice, _ := NewEntity("Alice", "", "Alice@gmail.com")
	fmt.Printf("%s", Alice.UserId)
	fmt.Printf("%x", Alice.Priv)
	fmt.Printf("%x", Alice.Pub)
}
