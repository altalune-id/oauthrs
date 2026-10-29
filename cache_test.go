package oauthrs

import (
	"crypto/sha256"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIntrospectionCache_FullEvictsOne(t *testing.T) {
	c := newIntrospectionCache()
	now := time.Unix(1_800_000_000, 0)
	until := now.Add(time.Minute)
	for i := range maxCachedTokens {
		c.put(sha256.Sum256([]byte(strconv.Itoa(i))), &Token{}, until)
	}
	fresh := sha256.Sum256([]byte("fresh"))
	c.put(fresh, &Token{Subject: "ana"}, until)
	assert.Len(t, c.entries, maxCachedTokens, "a full cache stays bounded")
	got, ok := c.get(fresh, now)
	assert.True(t, ok, "the new answer is cached, an older one gave way")
	assert.Equal(t, "ana", got.Subject)

	c.put(fresh, &Token{Subject: "bo"}, until)
	assert.Len(t, c.entries, maxCachedTokens, "replacing a cached key evicts nothing")
	_, ok = c.get(fresh, until)
	assert.False(t, ok, "an entry ends at its until")
}
