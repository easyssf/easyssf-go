package scim_test

import (
	"testing"

	"github.com/easyssf/easyssf-go/ssf"
	"github.com/easyssf/easyssf-go/ssf/eventtypes"
	"github.com/easyssf/easyssf-go/ssf/scim"
)

func token(subID ssf.Claims, events ssf.Claims) *ssf.EventToken {
	claims := ssf.Claims{"jti": "1", "iss": "https://t.example", "iat": float64(1700000000), "events": events}
	if subID != nil {
		claims["sub_id"] = subID
	}
	return ssf.EventTokenFromClaims(claims)
}

func scimSubject(uri string) *scim.Subject { return scim.SubjectOf(ssf.SubjectFrom(ssf.SCIM(uri, ""))) }

func TestEveryScimEventTypeHasAnOperationAndAnAlias(t *testing.T) {
	for _, known := range scim.Known {
		if scim.OperationOf(known.EventType) != known.Operation || eventtypes.AliasOf(known.EventType) == known.EventType || !scim.IsScimEvent(eventtypes.AliasOf(known.EventType)) {
			t.Fatal(known.EventType)
		}
		found := false
		for _, uri := range known.Operation.EventTypes() {
			found = found || uri == known.EventType
		}
		if !found {
			t.Fatal(known.EventType)
		}
	}
	if len(scim.Create.EventTypes()) != 2 || len(scim.Delete.EventTypes()) != 1 || scim.OperationOf("CaepSessionRevoked") != scim.Unknown {
		t.Fatal("operations")
	}
	if !scim.Create.IsProvisioning() || !scim.Deactivate.IsProvisioning() || scim.FeedAdd.IsProvisioning() || scim.FeedRemove.IsProvisioning() || scim.AsyncResponse.IsProvisioning() {
		t.Fatal("provisioning")
	}
}

func TestFullAndNoticeEvents(t *testing.T) {
	full := scim.Of("ScimProvCreateFull", scimSubject("/Users/1"), ssf.Claims{"data": map[string]any{"userName": "alice"}, "version": `W/"1"`})
	if !full.IsFull() || full.IsNotice() || full.Data()["userName"] != "alice" || full.Version() != `W/"1"` || len(full.Attributes()) != 0 ||
		full.Operation() != scim.Create || full.Subject().ID() != "1" {
		t.Fatal("full")
	}
	notice := scim.Of("ScimProvPatchNotice", nil, ssf.Claims{"attributes": []any{"emails", "name.familyName", float64(3)}})
	if !notice.IsNotice() || len(notice.Attributes()) != 2 || notice.Attributes()[1] != "name.familyName" || notice.Data() != nil {
		t.Fatal("notice")
	}
	del := scim.Of("ScimProvDelete", nil, nil)
	if del.IsFull() || del.IsNotice() || len(del.Payload()) != 0 || del.Version() != "" {
		t.Fatal("delete")
	}
	async := scim.Of("ScimMiscAsyncResponse", nil, ssf.Claims{"method": "POST", "status": "409", "response": map[string]any{"scimType": "uniqueness", "detail": "exists"}})
	if async.Method() != "POST" || async.Status() != "409" || async.Response()["scimType"] != "uniqueness" {
		t.Fatal("async")
	}
}

func TestFindsAllScimEventsOfASetInOrderAndIgnoresOthers(t *testing.T) {
	events := scim.InToken(token(ssf.SCIM("/Users/42", ""), ssf.Claims{eventtypes.ScimProvCreateFull: ssf.Claims{"data": ssf.Claims{}}, eventtypes.CaepSessionRevoked: ssf.Claims{}, eventtypes.ScimFeedAdd: ssf.Claims{}}))
	if len(events) != 2 || events[0].Operation() != scim.FeedAdd || events[1].Operation() != scim.Create || events[1].Subject().URI() != "/Users/42" {
		t.Fatalf("%v", events)
	}
	// subject is nil unless the SET has a scim subject
	if scim.InToken(token(ssf.IssSub("https://idp.example", "alice"), ssf.Claims{eventtypes.ScimProvDelete: ssf.Claims{}}))[0].Subject() != nil ||
		scim.InToken(token(nil, ssf.Claims{eventtypes.ScimProvDelete: ssf.Claims{}}))[0].Subject() != nil {
		t.Fatal("subject")
	}
	if scim.Of("ScimProvActivate", nil, nil).EventType() != eventtypes.ScimProvActivate || scim.Of("CaepSessionRevoked", nil, nil) != nil {
		t.Fatal("of")
	}
}

func TestSubject(t *testing.T) {
	s := scimSubject("/Users/2b2f880a")
	if s.ResourceType() != "Users" || s.ID() != "2b2f880a" || s.ExternalID() != "" {
		t.Fatal("uri")
	}
	s = scimSubject("https://scim.example/v2/Groups/g1?attributes=members")
	if s.ResourceType() != "Groups" || s.ID() != "g1" {
		t.Fatal("absolute")
	}
	s = scim.SubjectOf(ssf.SubjectFrom(ssf.Claims{"format": "scim", "uri": "/Users/from-uri", "id": "from-id", "externalId": "ext"}))
	if s.ID() != "from-id" || s.ExternalID() != "ext" {
		t.Fatal("id wins")
	}
	s = scim.SubjectOf(ssf.SubjectFrom(ssf.Claims{"format": "scim", "uri": "/Users/1", "userName": "alice", "active": true}))
	if s.Attribute("userName") != "alice" || s.Attribute("active") != "" || s.Claims()["active"] != true {
		t.Fatal("attributes")
	}
	s = scim.SubjectOf(ssf.SubjectFrom(ssf.Claims{"format": "scim", "externalId": "ext"}))
	if s.URI() != "" || s.ResourceType() != "" || s.ID() != "" {
		t.Fatal("no uri")
	}
	if scim.SubjectOf(ssf.SubjectFrom(ssf.Email("a@b.example"))) != nil || scim.SubjectOf(ssf.EmptySubject()) != nil || scim.SubjectFromIdentifier(nil) != nil {
		t.Fatal("only scim")
	}
	if scim.SubjectOf(ssf.SubjectFrom(ssf.Complex(ssf.SCIM("/Users/7", ""), ssf.Opaque("s1")))).ID() != "7" {
		t.Fatal("complex")
	}
}
