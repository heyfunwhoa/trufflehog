package gerrit

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/giturl"
	"github.com/trufflesecurity/trufflehog/v3/pkg/log"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/source_metadatapb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sanitizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

const (
	SourceType = sourcespb.SourceType_SOURCE_TYPE_GERRIT

	// gerritJSONPrefix is prepended to JSON REST responses to prevent XSS.
	gerritJSONPrefix = ")]}'"

	projectsPageSize = 100
)

// metaProjects are Gerrit's permission/config repositories and are not source code.
var metaProjects = map[string]struct{}{
	"All-Projects": {},
	"All-Users":    {},
}

type Source struct {
	name          string
	sourceID      sources.SourceID
	jobID         sources.JobID
	verify        bool
	endpoint      string
	user          string
	password      string
	authenticated bool
	projects      []string
	skipBinaries  bool
	skipArchives  bool
	concurrency   int
	client        *http.Client
	git           *git.Git
	scanOptions   *git.ScanOptions
	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

type gerritProjectInfo struct {
	ID           string `json:"id"`
	State        string `json:"state"`
	MoreProjects bool   `json:"_more_projects"`
}

// Ensure the Source satisfies the interfaces at compile time.
var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)
var _ sources.SourceUnitEnumChunker = (*Source)(nil)

// Type returns the type of source.
func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceID
}

func (s *Source) JobID() sources.JobID {
	return s.jobID
}

func (s *Source) WithScanOptions(scanOptions *git.ScanOptions) {
	s.scanOptions = scanOptions
}

// Init returns an initialized Gerrit source.
func (s *Source) Init(ctx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, concurrency int) error {
	s.name = name
	s.sourceID = sourceId
	s.jobID = jobId
	s.verify = verify
	s.concurrency = concurrency
	if s.concurrency == 0 {
		s.concurrency = 1
	}
	s.client = common.RetryableHTTPClientTimeout(10)

	if err := git.CmdCheck(); err != nil {
		return err
	}

	var conn sourcespb.Gerrit
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return fmt.Errorf("error unmarshalling connection: %w", err)
	}

	endpoint, err := normalizeEndpoint(conn.GetEndpoint())
	if err != nil {
		return err
	}
	s.endpoint = endpoint
	s.projects = conn.GetProjects()
	s.skipBinaries = conn.GetSkipBinaries()
	s.skipArchives = conn.GetSkipArchives()

	switch cred := conn.GetCredential().(type) {
	case *sourcespb.Gerrit_BasicAuth:
		s.user = cred.BasicAuth.GetUsername()
		s.password = cred.BasicAuth.GetPassword()
		if s.user == "" || s.password == "" {
			return fmt.Errorf("Gerrit basic auth requires both username and password")
		}
		s.authenticated = true
		log.RedactGlobally(s.password)
	case *sourcespb.Gerrit_Unauthenticated:
		s.authenticated = false
	default:
		// Proto default when credential is unset: treat as unauthenticated.
		s.authenticated = false
	}

	cfg := &git.Config{
		SourceName:   s.name,
		JobID:        s.jobID,
		SourceID:     s.sourceID,
		SourceType:   s.Type(),
		Verify:       s.verify,
		SkipBinaries: s.skipBinaries,
		SkipArchives: s.skipArchives,
		Concurrency:  concurrency,
		SourceMetadataFunc: func(info git.SourceMetadataInfo) *source_metadatapb.MetaData {
			return &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Gerrit{
					Gerrit: &source_metadatapb.Gerrit{
						Commit:    sanitizer.UTF8(info.Commit),
						File:      sanitizer.UTF8(info.File),
						Email:     sanitizer.UTF8(info.Email),
						Project:   sanitizer.UTF8(s.projectFromCloneURL(info.Repository)),
						Timestamp: sanitizer.UTF8(info.Timestamp),
						Line:      info.Line,
					},
				},
			}
		},
		AuthInUrl: true,
	}
	s.git = git.NewGit(cfg)
	return nil
}

// Chunks enumerates Gerrit projects and scans their git history.
func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	var units []sources.SourceUnit
	reporter := sources.VisitorReporter{
		VisitUnit: func(_ context.Context, unit sources.SourceUnit) error {
			units = append(units, unit)
			return nil
		},
		VisitErr: func(ctx context.Context, err error) error {
			ctx.Logger().Error(err, "error enumerating Gerrit project")
			return nil
		},
	}
	if err := s.Enumerate(ctx, reporter); err != nil {
		return err
	}

	scanErrs := sources.NewScanErrors()
	eg := new(errgroup.Group)
	eg.SetLimit(s.concurrency)
	for _, unit := range units {
		eg.Go(func() error {
			if err := s.ChunkUnit(ctx, unit, sources.ChanReporter{Ch: chunksChan}); err != nil {
				scanErrs.Add(err)
			}
			return nil
		})
	}
	_ = eg.Wait()
	if scanErrs.Count() > 0 {
		ctx.Logger().V(2).Info("encountered errors while scanning Gerrit", "count", scanErrs.Count(), "errors", scanErrs)
		return fmt.Errorf("encountered %d error(s) while scanning Gerrit", scanErrs.Count())
	}
	return nil
}

// Enumerate reports Gerrit projects to scan. If none are configured, it lists
// all accessible code projects from the Gerrit REST API.
func (s *Source) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	projects := s.projects
	if len(projects) == 0 {
		listed, err := s.listProjects(ctx)
		if err != nil {
			return err
		}
		projects = listed
	}

	for _, project := range projects {
		normalized, err := giturl.NormalizeGerritProject(project)
		if err != nil {
			if err := reporter.UnitErr(ctx, err); err != nil {
				return err
			}
			continue
		}
		if isMetaProject(normalized) {
			ctx.Logger().V(3).Info("skipping Gerrit meta project", "project", normalized)
			continue
		}
		unit := git.SourceUnit{Kind: git.UnitRepo, ID: s.cloneURL(normalized)}
		if err := reporter.UnitOk(ctx, unit); err != nil {
			return err
		}
	}
	return nil
}

// ChunkUnit clones and scans a single Gerrit project.
func (s *Source) ChunkUnit(ctx context.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	repoURL, _ := unit.SourceUnitID()
	ctx = context.WithValue(ctx, "repo", repoURL)

	var (
		path string
		repo *gogit.Repository
		err  error
	)
	if s.authenticated {
		path, repo, err = git.CloneRepoUsingToken(ctx, s.password, repoURL, "", s.user, true)
	} else {
		path, repo, err = git.CloneRepoUsingUnauthenticated(ctx, repoURL, "")
	}
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(path) }()

	return s.git.ScanRepo(ctx, repo, path, s.scanOptions, reporter)
}

func (s *Source) listProjects(ctx context.Context) ([]string, error) {
	var projects []string
	skip := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		page, rawCount, more, err := s.listProjectsPage(ctx, skip)
		if err != nil {
			return nil, err
		}
		projects = append(projects, page...)
		if !more || rawCount == 0 {
			break
		}
		skip += rawCount
	}
	ctx.Logger().Info("enumerated Gerrit projects", "count", len(projects))
	return projects, nil
}

func (s *Source) listProjectsPage(ctx context.Context, skip int) ([]string, int, bool, error) {
	apiURL, err := url.Parse(s.projectsAPIPath())
	if err != nil {
		return nil, 0, false, err
	}
	query := apiURL.Query()
	query.Set("n", fmt.Sprintf("%d", projectsPageSize))
	query.Set("S", fmt.Sprintf("%d", skip))
	apiURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL.String(), nil)
	if err != nil {
		return nil, 0, false, err
	}
	req.Header.Set("Accept", "application/json")
	if s.authenticated {
		req.SetBasicAuth(s.user, s.password)
	}

	res, err := s.client.Do(req)
	if err != nil {
		return nil, 0, false, fmt.Errorf("failed to list Gerrit projects: %w", err)
	}
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, 0, false, fmt.Errorf("failed to read Gerrit projects response: %w", err)
	}

	if res.StatusCode == http.StatusUnauthorized || res.StatusCode == http.StatusForbidden {
		return nil, 0, false, fmt.Errorf("Gerrit authentication failed (HTTP %d); use an HTTP password from Settings → HTTP Credentials", res.StatusCode)
	}
	if res.StatusCode != http.StatusOK {
		return nil, 0, false, fmt.Errorf("unexpected Gerrit response listing projects: HTTP %d: %s", res.StatusCode, truncate(string(body), 256))
	}

	decoded, err := decodeGerritJSON(body)
	if err != nil {
		return nil, 0, false, err
	}

	var parsed map[string]gerritProjectInfo
	if err := json.Unmarshal(decoded, &parsed); err != nil {
		return nil, 0, false, fmt.Errorf("failed to parse Gerrit projects: %w", err)
	}

	var (
		names []string
		more  bool
	)
	for name, info := range parsed {
		if info.MoreProjects {
			more = true
		}
		if strings.EqualFold(info.State, "HIDDEN") {
			continue
		}
		normalized, err := giturl.NormalizeGerritProject(name)
		if err != nil {
			continue
		}
		if isMetaProject(normalized) {
			continue
		}
		names = append(names, normalized)
	}
	return names, len(parsed), more, nil
}

func (s *Source) projectsAPIPath() string {
	if s.authenticated {
		return s.endpoint + "/a/projects/"
	}
	return s.endpoint + "/projects/"
}

func (s *Source) cloneURL(project string) string {
	encoded := encodeProjectPath(project)
	if s.authenticated {
		return s.endpoint + "/a/" + encoded
	}
	return s.endpoint + "/" + encoded
}

func (s *Source) projectFromCloneURL(cloneURL string) string {
	trimmed := strings.TrimSuffix(cloneURL, ".git")
	for _, prefix := range []string{s.endpoint + "/a/", s.endpoint + "/"} {
		if name, ok := strings.CutPrefix(trimmed, prefix); ok {
			if decoded, err := url.PathUnescape(name); err == nil {
				return decoded
			}
			return name
		}
	}
	if normalized, err := giturl.NormalizeGerritProject(cloneURL); err == nil {
		return normalized
	}
	return cloneURL
}

func encodeProjectPath(project string) string {
	parts := strings.Split(project, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func normalizeEndpoint(endpoint string) (string, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", fmt.Errorf("Gerrit endpoint is required")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("invalid Gerrit endpoint: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("Gerrit endpoint must be an http(s) URL, got %q", endpoint)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("invalid Gerrit endpoint %q: missing host", endpoint)
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return strings.TrimRight(parsed.String(), "/"), nil
}

func decodeGerritJSON(body []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(body))
	if after, ok := strings.CutPrefix(trimmed, gerritJSONPrefix); ok {
		trimmed = strings.TrimSpace(after)
	}
	if trimmed == "" {
		return nil, fmt.Errorf("empty Gerrit JSON response")
	}
	return []byte(trimmed), nil
}

func isMetaProject(project string) bool {
	_, ok := metaProjects[project]
	return ok
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
