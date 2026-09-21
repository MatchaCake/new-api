package openai

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/MoeForge/moego/ojson"
)

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
		if output := ojson.GetBytes(payload, outputPath); output.IsArray() {
			for i := range output.Array() {
				paths = append(paths, fmt.Sprintf("%s.%d.id", outputPath, i))
			}
		}
	}
	for _, path := range paths {
		id := ojson.GetBytes(payload, path)
		if id.Type != ojson.String || !collisionProneResponsesItemID.MatchString(id.Str) {
			continue
		}
		if patched, err := ojson.SetBytes(payload, path, responseID+"_"+id.Str); err == nil {
			payload = patched
		}
	}
	return payload
}
