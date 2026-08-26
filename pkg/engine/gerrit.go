package engine

import (
	"fmt"
	"runtime"

	gogit "github.com/go-git/go-git/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/trufflesecurity/trufflehog/v3/pkg/context"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/credentialspb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/sourcespb"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/gerrit"
	"github.com/trufflesecurity/trufflehog/v3/pkg/sources/git"
)

// ScanGerrit scans Gerrit projects with the provided configuration.
func (e *Engine) ScanGerrit(ctx context.Context, c sources.GerritConfig) (sources.JobProgressRef, error) {
	if c.Endpoint == "" {
		return sources.JobProgressRef{}, fmt.Errorf("Gerrit endpoint is required")
	}

	logOptions := &gogit.LogOptions{}
	opts := []git.ScanOption{
		git.ScanOptionFilter(c.Filter),
		git.ScanOptionLogOptions(logOptions),
	}
	if c.BaseRef != "" {
		opts = append(opts, git.ScanOptionBaseHash(c.BaseRef))
	}
	if c.HeadRef != "" {
		opts = append(opts, git.ScanOptionHeadCommit(c.HeadRef))
	}
	scanOptions := git.NewScanOptions(opts...)

	connection := &sourcespb.Gerrit{
		Endpoint:     c.Endpoint,
		Projects:     c.Projects,
		SkipBinaries: c.SkipBinaries,
		SkipArchives: c.SkipArchives,
	}

	switch {
	case c.Username != "" && c.Password != "":
		connection.Credential = &sourcespb.Gerrit_BasicAuth{
			BasicAuth: &credentialspb.BasicAuth{
				Username: c.Username,
				Password: c.Password,
			},
		}
	case c.Username != "" || c.Password != "":
		return sources.JobProgressRef{}, fmt.Errorf("Gerrit basic auth requires both username and password")
	default:
		connection.Credential = &sourcespb.Gerrit_Unauthenticated{
			Unauthenticated: &credentialspb.Unauthenticated{},
		}
	}

	var conn anypb.Any
	if err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{}); err != nil {
		ctx.Logger().Error(err, "failed to marshal Gerrit connection")
		return sources.JobProgressRef{}, err
	}

	sourceName := "trufflehog - gerrit"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, gerrit.SourceType)

	gerritSource := &gerrit.Source{}
	if err := gerritSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
		return sources.JobProgressRef{}, err
	}
	gerritSource.WithScanOptions(scanOptions)
	return e.sourceManager.EnumerateAndScan(ctx, sourceName, gerritSource)
}
