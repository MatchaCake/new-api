package openai

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"regexp"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/logger"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relay/helper"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func OaiResponsesHandler(c *gin.Context, info *relaycommon.RelayInfo, resp *http.Response) (*dto.Usage, *types.NewAPIError) {
	defer service.CloseResponseBodyGracefully(resp)

	// read response body
	var responsesResponse dto.OpenAIResponsesResponse
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, types.NewOpenAIError(err, types.ErrorCodeReadResponseBodyFailed, http.StatusInternalServerError)
	}
	err = common.Unmarshal(responseBody, &responsesResponse)
	if err != nil {
		return nil, types.NewOpenAIError(err, types.ErrorCodeBadResponseBody, http.StatusInternalServerError)
	}
	if oaiError := responsesResponse.GetOpenAIError(); oaiError != nil && oaiError.Type != "" {
		return nil, types.WithOpenAIError(*oaiError, resp.StatusCode)
	}

	info.ObserveResponseModel(responsesResponse.Model)
	responseBody = rewriteSGLangResponsesCreatedAt(info, responseBody, "created_at", responsesResponse.CreatedAt)
	responseBody = namespaceResponsesItemIDs(responseBody, responsesResponse.ID)

	// 写入新的 response body
	service.IOCopyBytesGracefully(c, resp, responseBody)

	// compute usage
	usage := &dto.Usage{}
	service.ApplyResponsesUsage(usage, responsesResponse.Usage)
	// Count actual tool invocations from Output (not tool declarations).
	for _, output := range responsesResponse.Output {
		switch output.Type {
		case dto.BuildInCallWebSearchCall:
			info.CountBillableToolCall(dto.BuildInCallWebSearchCall, "")
		case dto.BuildInCallFileSearchCall:
			info.CountBillableToolCall(dto.BuildInCallFileSearchCall, "")
		case dto.BuildInCallFunctionCall:
			info.CountBillableToolCall(dto.BuildInCallFunctionCall, output.Name)
		}
	}

	imageCounter := &relaycommon.ImageGenerationCallCounter{}
	if !relaycommon.IsNonBillableResponsesStatus(responsesResponse.Status) {
		for i := range responsesResponse.Output {
			idx := i
			imageCounter.Observe(&responsesResponse.Output[i], &idx)
		}
	}
	imageCounter.Commit(info)

	return usage, nil
}

func OaiResponsesStreamHandler(c *gin.Context, info *relaycommon.RelayInfo, resp *http.Response) (*dto.Usage, *types.NewAPIError) {
	if resp == nil || resp.Body == nil {
		logger.LogError(c, "invalid response or response body")
		return nil, types.NewError(fmt.Errorf("invalid response"), types.ErrorCodeBadResponse)
	}

	defer service.CloseResponseBodyGracefully(resp)

	accumulator := service.NewResponsesUsageAccumulator(info)

	// The response id arrives on the response.* envelope events (response.created
	// first); item events in between only carry item ids, so remember it here.
	responseID := ""
	helper.StreamScannerHandler(c, resp, info, func(data string, sr *helper.StreamResult) {

		// 检查当前数据是否包含 completed 状态和 usage 信息
		var streamResponse dto.ResponsesStreamResponse
		if err := common.UnmarshalJsonStr(data, &streamResponse); err != nil {
			logger.LogError(c, "failed to unmarshal stream response: "+err.Error())
			sr.Error(err)
			return
		}
		if streamResponse.Response != nil {
			data = string(rewriteSGLangResponsesCreatedAt(info, []byte(data), "response.created_at", streamResponse.Response.CreatedAt))
			if streamResponse.Response.ID != "" {
				responseID = streamResponse.Response.ID
			}
		}
		data = string(namespaceResponsesItemIDs([]byte(data), responseID))
		sendResponsesStreamData(c, streamResponse, data)
		accumulator.Observe(&streamResponse)
	})

	common.SetContextKey(c, constant.ContextKeyResponseStreamStatus, info.StreamStatus)
	info.StreamStatus.RequireTerminal()
	return accumulator.Finish(), nil
}

// collisionProneResponsesItemID matches the bare sequential output item ids
// ("item_0", "item_1", …) some OpenAI-compatible upstreams emit. They restart
// from zero on every response, so consecutive responses within one client
// conversation reuse the same ids and break clients that track output items by
// id across calls (Codex, for example, reorders turns when ids collide).
// OpenAI itself namespaces item ids ("msg_…", "rs_…", "fc_…"), so genuine
// upstream ids never match and pass through untouched.
var collisionProneResponsesItemID = regexp.MustCompile(`^item_\d+$`)

// namespaceResponsesItemIDs prefixes collision-prone output item ids with the
// upstream response id, which is unique per response, so the ids clients see
// stay unique across responses. It rewrites the item payloads ("item.id" on
// output_item events, "output.N.id" on response snapshots) together with the
// "item_id" references delta events carry. call_id values are never touched:
// they must round-trip to the upstream for tool-output correlation.
func namespaceResponsesItemIDs(payload []byte, responseID string) []byte {
	if responseID == "" || !bytes.Contains(payload, []byte(`":"item_`)) {
		return payload
	}
	paths := []string{"item.id", "item_id"}
	for _, outputPath := range []string{"response.output", "output"} {
		if output := gjson.GetBytes(payload, outputPath); output.IsArray() {
			for i := range output.Array() {
				paths = append(paths, fmt.Sprintf("%s.%d.id", outputPath, i))
			}
		}
	}
	for _, path := range paths {
		id := gjson.GetBytes(payload, path)
		if id.Type != gjson.String || !collisionProneResponsesItemID.MatchString(id.Str) {
			continue
		}
		if patched, err := sjson.SetBytes(payload, path, responseID+"_"+id.Str); err == nil {
			payload = patched
		}
	}
	return payload
}

func rewriteSGLangResponsesCreatedAt(info *relaycommon.RelayInfo, payload []byte, path string, createdAt dto.IntValue) []byte {
	if info.GetChannelType() != constant.ChannelTypeSGLang {
		return payload
	}
	if !gjson.GetBytes(payload, path).Exists() {
		return payload
	}
	patched, err := sjson.SetBytes(payload, path, int(createdAt))
	if err != nil {
		return payload
	}
	return patched
}
