package openai

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runResponsesItemIDStream(t *testing.T, events ...string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	oldTimeout := constant.StreamingTimeout
	constant.StreamingTimeout = 30
	t.Cleanup(func() {
		constant.StreamingTimeout = oldTimeout
	})

	var body strings.Builder
	for _, event := range events {
		body.WriteString("data: ")
		body.WriteString(event)
		body.WriteString("\n\n")
	}
	body.WriteString("data: [DONE]\n\n")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Set(common.RequestIdKey, "responses-item-id-test")
	info := &relaycommon.RelayInfo{
		OriginModelName: "devin-swe-2",
		DisablePing:     true,
		ChannelMeta: &relaycommon.ChannelMeta{
			ChannelType:       constant.ChannelTypeOpenAI,
			UpstreamModelName: "devin-swe-2",
		},
	}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(body.String())),
		Header:     http.Header{"Content-Type": []string{"text/event-stream"}},
	}

	_, apiErr := OaiResponsesStreamHandler(c, info, resp)
	require.Nil(t, apiErr)
	return w
}

func TestOaiResponsesStreamHandlerNamespacesCollisionProneItemIDs(t *testing.T) {
	w := runResponsesItemIDStream(
		t,
		`{"type":"response.created","response":{"id":"interaction_abc","object":"response","status":"in_progress","output":[]}}`,
		`{"type":"response.output_item.added","output_index":0,"item":{"id":"item_0","type":"reasoning","status":"in_progress","summary":[]}}`,
		`{"type":"response.output_item.done","output_index":0,"item":{"id":"item_0","type":"reasoning","summary":[]}}`,
		`{"type":"response.output_item.added","output_index":1,"item":{"id":"item_1","type":"message","status":"in_progress","role":"assistant","content":[]}}`,
		`{"type":"response.output_text.delta","output_index":1,"content_index":0,"item_id":"item_1","delta":"Hi!"}`,
		`{"type":"response.output_item.added","output_index":2,"item":{"id":"item_2","type":"function_call","call_id":"call_9","name":"lookup","arguments":""}}`,
		`{"type":"response.completed","response":{"id":"interaction_abc","status":"completed","output":[{"id":"item_0","type":"reasoning","summary":[]},{"id":"item_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi!"}]},{"id":"item_2","type":"function_call","call_id":"call_9","name":"lookup","arguments":"{}"}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`,
	)

	streamBody := w.Body.String()
	assert.NotContains(t, streamBody, `"item_0"`)
	assert.NotContains(t, streamBody, `"item_1"`)
	assert.NotContains(t, streamBody, `"item_2"`)
	assert.Contains(t, streamBody, `"id":"interaction_abc_item_0"`)
	assert.Contains(t, streamBody, `"id":"interaction_abc_item_1"`)
	assert.Contains(t, streamBody, `"item_id":"interaction_abc_item_1"`)
	assert.Contains(t, streamBody, `"id":"interaction_abc_item_2"`)
	// call_id must survive untouched so tool outputs still correlate upstream.
	assert.Contains(t, streamBody, `"call_id":"call_9"`)
	// The response's own id is not an output item id and stays as-is.
	assert.Contains(t, streamBody, `"id":"interaction_abc"`)
}

func TestOaiResponsesStreamHandlerKeepsNamespacedItemIDs(t *testing.T) {
	w := runResponsesItemIDStream(
		t,
		`{"type":"response.created","response":{"id":"resp_123","object":"response","status":"in_progress","output":[]}}`,
		`{"type":"response.output_item.added","output_index":0,"item":{"id":"msg_abc123","type":"message","status":"in_progress","role":"assistant","content":[]}}`,
		`{"type":"response.output_text.delta","output_index":0,"content_index":0,"item_id":"msg_abc123","delta":"Hi!"}`,
		`{"type":"response.completed","response":{"id":"resp_123","status":"completed","output":[{"id":"msg_abc123","type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi!"}]}]}}`,
	)

	streamBody := w.Body.String()
	assert.Contains(t, streamBody, `"id":"msg_abc123"`)
	assert.NotContains(t, streamBody, "resp_123_msg_abc123")
}

func TestOaiResponsesStreamHandlerLeavesItemIDsWithoutResponseID(t *testing.T) {
	w := runResponsesItemIDStream(
		t,
		`{"type":"response.output_item.added","output_index":0,"item":{"id":"item_0","type":"message","status":"in_progress","role":"assistant","content":[]}}`,
		`{"type":"response.output_text.delta","output_index":0,"content_index":0,"item_id":"item_0","delta":"Hi!"}`,
	)

	assert.Contains(t, w.Body.String(), `"id":"item_0"`)
}

func TestOaiResponsesHandlerNamespacesCollisionProneItemIDs(t *testing.T) {
	gin.SetMode(gin.TestMode)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)

	info := &relaycommon.RelayInfo{OriginModelName: "devin-swe-2"}
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Body: io.NopCloser(strings.NewReader(
			`{"id":"interaction_abc","object":"response","status":"completed","output":[{"id":"item_0","type":"reasoning","summary":[]},{"id":"item_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"Hi!"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`,
		)),
		Header: http.Header{"Content-Type": []string{"application/json"}},
	}

	_, apiErr := OaiResponsesHandler(c, info, resp)
	require.Nil(t, apiErr)
	responseBody := w.Body.String()
	assert.Contains(t, responseBody, `"id":"interaction_abc"`)
	assert.Contains(t, responseBody, `"id":"interaction_abc_item_0"`)
	assert.Contains(t, responseBody, `"id":"interaction_abc_item_1"`)
	assert.NotContains(t, responseBody, `"item_0"`)
	assert.NotContains(t, responseBody, `"item_1"`)
}
