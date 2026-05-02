// ©AngelaMos | 2026
// parser_test.go

package wikipedia_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/carterperez-dev/monitor-the-situation/backend/internal/collectors/wikipedia"
)

func TestParser_ExtractsITNEntriesFromFixture(t *testing.T) {
	body, err := os.ReadFile("testdata/itn_response.json")
	require.NoError(t, err)

	resp, err := wikipedia.DecodeResponse(body)
	require.NoError(t, err)
	require.NotZero(t, resp.RevID)

	entries := wikipedia.ParseEntries(resp.HTML)
	require.GreaterOrEqual(t, len(entries), 1)
	for _, e := range entries {
		require.NotEmpty(t, e.Text)
	}
	hasLink := false
	for _, e := range entries {
		if e.ArticleSlug != "" {
			hasLink = true
			break
		}
	}
	require.True(t, hasLink, "at least one entry should carry an article slug")
}

func TestParser_HandlesEmptyHTML(t *testing.T) {
	entries := wikipedia.ParseEntries("")
	require.Empty(t, entries)
}

func TestParser_StripsHTMLTagsFromText(t *testing.T) {
	entries := wikipedia.ParseEntries(`<ul><li>Plain <b>bold</b> headline with <a href="/wiki/Topic">link</a>.</li></ul>`)
	require.Len(t, entries, 1)
	require.Contains(t, entries[0].Text, "Plain")
	require.Contains(t, entries[0].Text, "bold")
	require.Contains(t, entries[0].Text, "link")
	require.NotContains(t, entries[0].Text, "<b>")
	require.Equal(t, "Topic", entries[0].ArticleSlug)
}

func TestParser_SkipsListItemsWithoutLinks(t *testing.T) {
	entries := wikipedia.ParseEntries(`<ul><li>Has <a href="/wiki/Foo">link</a></li><li>No link here</li></ul>`)
	require.Len(t, entries, 2)
	require.Equal(t, "Foo", entries[0].ArticleSlug)
	require.Empty(t, entries[1].ArticleSlug)
}
