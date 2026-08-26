package gerrit

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

func TestDecodeGerritJSON(t *testing.T) {
	t.Parallel()

	got, err := decodeGerritJSON([]byte(")]}'\n{\"foo\":{}}"))
	require.NoError(t, err)
	assert.Equal(t, `{"foo":{}}`, string(got))

	got, err = decodeGerritJSON([]byte(`{"foo":{}}`))
	require.NoError(t, err)
	assert.Equal(t, `{"foo":{}}`, string(got))

	_, err = decodeGerritJSON([]byte(")]}'\n"))
	require.Error(t, err)
}

func TestNormalizeEndpoint(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "https://gerrit.example.com", want: "https://gerrit.example.com"},
		{in: "https://gerrit.example.com/", want: "https://gerrit.example.com"},
		{in: "https://gerrit.example.com/gerrit/", want: "https://gerrit.example.com/gerrit"},
		{in: "http://localhost:8080", want: "http://localhost:8080"},
		{in: "gerrit.example.com", wantErr: true},
		{in: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := normalizeEndpoint(tt.in)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestCloneURLAndProjectFromCloneURL(t *testing.T) {
	t.Parallel()

	s := &Source{endpoint: "https://gerrit.example.com", authenticated: true}
	assert.Equal(t, "https://gerrit.example.com/a/foo/bar", s.cloneURL("foo/bar"))
	assert.Equal(t, "foo/bar", s.projectFromCloneURL("https://gerrit.example.com/a/foo/bar"))

	s.authenticated = false
	assert.Equal(t, "https://gerrit.example.com/platform%20svc/api", s.cloneURL("platform svc/api"))
	assert.Equal(t, "platform svc/api", s.projectFromCloneURL("https://gerrit.example.com/platform%20svc/api"))
}

func TestIsMetaProject(t *testing.T) {
	t.Parallel()
	assert.True(t, isMetaProject("All-Projects"))
	assert.True(t, isMetaProject("All-Users"))
	assert.False(t, isMetaProject("my/project"))
}

func TestEnumerateConfiguredProjects(t *testing.T) {
	t.Parallel()

	s := mustInit(t, "https://gerrit.example.com", "", "", []string{"foo/bar", "All-Projects", "/baz.git"})
	var got []string
	reporter := sources.VisitorReporter{
		VisitUnit: func(_ context.Context, unit sources.SourceUnit) error {
			id, kind := unit.SourceUnitID()
			assert.Equal(t, git.UnitRepo, kind)
			got = append(got, id)
			return nil
		},
		VisitErr: func(_ context.Context, err error) error {
			t.Errorf("unexpected unit error: %v", err)
			return nil
		},
	}
	require.NoError(t, s.Enumerate(context.Background(), reporter))
	assert.ElementsMatch(t, []string{
		"https://gerrit.example.com/foo/bar",
		"https://gerrit.example.com/baz",
	}, got)
}

func TestListProjectsPaginationAndFilters(t *testing.T) {
	t.Parallel()

	var seenSkips []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/projects/", r.URL.Path)
		seenSkips = append(seenSkips, r.URL.Query().Get("S"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("S") {
		case "0":
			_, _ = io.WriteString(w, `)]}'
{
  "All-Projects": {"id": "All-Projects", "state": "ACTIVE"},
  "hidden/one": {"id": "hidden%2Fone", "state": "HIDDEN"},
  "team/alpha": {"id": "team%2Falpha", "state": "ACTIVE", "_more_projects": true}
}`)
		case "3":
			_, _ = io.WriteString(w, `)]}'
{
  "All-Users": {"id": "All-Users"},
  "team/beta": {"id": "team%2Fbeta", "state": "ACTIVE"}
}`)
		default:
			t.Errorf("unexpected skip %q", r.URL.Query().Get("S"))
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	t.Cleanup(server.Close)

	s := mustInit(t, server.URL, "", "", nil)
	projects, err := s.listProjects(context.Background())
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"team/alpha", "team/beta"}, projects)
	assert.Equal(t, []string{"0", "3"}, seenSkips)
}

func TestListProjectsAuthenticatedUsesPrefixAndBasicAuth(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/a/projects/", r.URL.Path)
		user, pass, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "scanner", user)
		assert.Equal(t, "http-password", pass)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `)]}'
{"apps/web": {"id": "apps%2Fweb", "state": "ACTIVE"}}`)
	}))
	t.Cleanup(server.Close)

	s := mustInit(t, server.URL, "scanner", "http-password", nil)
	var got []string
	reporter := sources.VisitorReporter{
		VisitUnit: func(_ context.Context, unit sources.SourceUnit) error {
			id, _ := unit.SourceUnitID()
			got = append(got, id)
			return nil
		},
	}
	require.NoError(t, s.Enumerate(context.Background(), reporter))
	assert.Equal(t, []string{server.URL + "/a/apps/web"}, got)
}

func TestListProjectsAuthError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "Unauthorized")
	}))
	t.Cleanup(server.Close)

	s := mustInit(t, server.URL, "scanner", "bad", nil)
	_, err := s.listProjects(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authentication failed")
}

func TestInitRequiresCompleteBasicAuth(t *testing.T) {
	t.Parallel()

	conn := &sourcespb.Gerrit{
		Endpoint: "https://gerrit.example.com",
		Credential: &sourcespb.Gerrit_BasicAuth{
			BasicAuth: &credentialspb.BasicAuth{Username: "only-user"},
		},
	}
	var anyConn anypb.Any
	require.NoError(t, anypb.MarshalFrom(&anyConn, conn, proto.MarshalOptions{}))
	err := (&Source{}).Init(context.Background(), "gerrit", 1, 1, true, &anyConn, runtime.NumCPU())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "username and password")
}

func mustInit(t *testing.T, endpoint, user, pass string, projects []string) *Source {
	t.Helper()
	conn := &sourcespb.Gerrit{
		Endpoint: endpoint,
		Projects: projects,
	}
	if user != "" || pass != "" {
		conn.Credential = &sourcespb.Gerrit_BasicAuth{
			BasicAuth: &credentialspb.BasicAuth{Username: user, Password: pass},
		}
	} else {
		conn.Credential = &sourcespb.Gerrit_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		}
	}
	var anyConn anypb.Any
	require.NoError(t, anypb.MarshalFrom(&anyConn, conn, proto.MarshalOptions{}))
	s := &Source{}
	require.NoError(t, s.Init(context.Background(), "trufflehog - gerrit", 1, 1, true, &anyConn, 1))
	return s
}
