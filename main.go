package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/SgtCoDFish/cert-manager-dashboard/pkg/logging"

	"github.com/google/go-github/v71/github"
	"golang.org/x/sync/errgroup"
)

const (
	maintainencePeriod = 60 * time.Minute

	twoDays    = 2 * 30
	thirtyDays = 24 * 30

	ntfyTopic = "cert-manager-warnings"
)

type repoConfigurer func(*targetRepo)

func WithHasReleases(hasReleases bool) repoConfigurer {
	return func(t *targetRepo) {
		t.HasReleases = hasReleases
	}
}

func WithVersionFilter(versionFilter string) repoConfigurer {
	return func(t *targetRepo) {
		t.VersionFilter = versionFilter
	}
}

func WithFriendlyName(name string) repoConfigurer {
	return func(t *targetRepo) {
		t.FriendlyName = name
	}
}

func WithHasGovulncheck(hasGovulncheck bool) repoConfigurer {
	return func(t *targetRepo) {
		t.HasGovulncheck = hasGovulncheck
	}
}

var (
	// targetList is the list of repos we want to check
	targetList = []*targetRepo{
		TargetRepo("cert-manager", "cert-manager", WithFriendlyName("master"), WithHasReleases(false)),
		TargetRepo("cert-manager", "cert-manager", WithVersionFilter(`v1\.18\.[0-9]+`), WithFriendlyName("release-1.18"), WithHasGovulncheck(false)),
		TargetRepo("cert-manager", "cert-manager", WithVersionFilter(`v1\.17\.[0-9]+`), WithFriendlyName("release-1.17"), WithHasGovulncheck(false)),
		TargetRepo("cert-manager", "trust-manager"),
		TargetRepo("cert-manager", "approver-policy"),
		TargetRepo("cert-manager", "csi-driver"),
		TargetRepo("cert-manager", "csi-driver-spiffe"),
		TargetRepo("cert-manager", "istio-csr"),
		TargetRepo("cert-manager", "cmctl"),
		TargetRepo("cert-manager", "google-cas-issuer"),
		TargetRepo("cert-manager", "openshift-routes"),
		TargetRepo("cert-manager", "issuer-lib", WithHasReleases(false)),
		TargetRepo("cert-manager", "csi-lib", WithHasReleases(false)),
	}

	//go:embed templates/index.html
	indexTemplateRaw string

	//go:embed static/robots.txt
	robotsTXTData []byte

	//go:embed static/favicon.ico
	faviconData []byte

	//go:embed static/css/bootstrap-v3.4.1.min.css
	bootstrapV341CSSData []byte

	lastNtfy string

	lastRunTmpl = template.Must(template.New("lastRunTmpl").Parse(`<a href="{{ .LastRun.GetHTMLURL }}" title="Latest run of govulncheck for {{ .RepoName }}" target="_blank">{{ .LastRun.GetHeadBranch }}</a>`))

	latestReleaseTmpl = template.Must(template.New("latestReleaseTmpl").Parse(`<a href="{{ .LastRelease.GetHTMLURL }}" title="Latest release for {{ .RepoName }}" target="_blank">{{ .LastRelease.GetTagName }}</a>`))
)

type targetRepo struct {
	OrgName  string
	RepoName string

	FriendlyName string

	HasGovulncheck bool
	HasReleases    bool

	GovulncheckWorkflowName string

	LastRun *github.WorkflowRun

	LastRelease *github.RepositoryRelease

	VersionFilter string
}

func (tr *targetRepo) String() string {
	suffix := ""

	if tr.FriendlyName != "" {
		suffix = fmt.Sprintf(" (%s)", tr.FriendlyName)
	}

	return fmt.Sprintf("%s/%s%s", tr.OrgName, tr.RepoName, suffix)
}

func (tr *targetRepo) BootstrapClass() string {
	cls, _ := tr.warnings()
	return cls
}

func (tr *targetRepo) WarningMessage() string {
	_, wrn := tr.warnings()
	return wrn
}

func (tr *targetRepo) LastTag() string {
	if !tr.HasReleases || tr.LastRelease == nil {
		return "N/A"
	}

	return tr.LastRelease.GetTagName()
}

func (tr *targetRepo) LastReleaseTime() string {
	if !tr.HasReleases || tr.LastRelease == nil {
		return "N/A"
	}

	return tr.LastRelease.GetCreatedAt().Time.UTC().Format(time.DateOnly)
}

func (tr *targetRepo) LastGovulncheckTime() string {
	if !tr.HasGovulncheck || tr.LastRun == nil {
		return "N/A"
	}

	return tr.LastRun.GetCreatedAt().Time.UTC().Format(time.DateTime)
}

func (tr *targetRepo) GovulncheckHead() template.HTML {
	if !tr.HasGovulncheck {
		return "N/A"
	}

	if tr.LastRun == nil {
		return "No runs found"
	}

	buf := &bytes.Buffer{}

	err := lastRunTmpl.Execute(buf, tr)
	if err != nil {
		return "Failed to render template"
	}

	// NB: template.HTML can be dangerous, but this is safe since this is output from "template/html.Template.Execute"
	return template.HTML(buf.String())
}

func (tr *targetRepo) LatestReleaseLink() template.HTML {
	if !tr.HasReleases {
		return "N/A"
	}

	if tr.LastRelease == nil {
		return "No release found"
	}

	buf := &bytes.Buffer{}

	err := latestReleaseTmpl.Execute(buf, tr)
	if err != nil {
		return "Failed to render template"
	}

	// NB: template.HTML can be dangerous, but this is safe since this is output from "template/html.Template.Execute"
	return template.HTML(buf.String())
}

// warnings returns a bootstrap class[1] and a reason if there are any
// warnings which should be shown for this repo. Can return empty strings
// if no warnings are needed.
// [1] https://getbootstrap.com/docs/3.4/css/#tables-contextual-classes
func (tr *targetRepo) warnings() (string, string) {
	if tr.HasGovulncheck {
		if tr.LastRun == nil {
			return "danger", "no data for last govulncheck run"
		} else if tr.LastRun.GetConclusion() != "success" {
			return "danger", "last govulncheck run not successful"
		} else if time.Since(tr.LastRun.GetCreatedAt().Time).Hours() > twoDays {
			return "danger", "govulncheck stale for more than two days"
		}
	}

	if tr.HasReleases {
		if tr.LastRelease == nil {
			return "danger", "no data for last release"
		}

		if time.Since(tr.LastRelease.GetCreatedAt().Time).Hours() > 2*thirtyDays {
			return "danger", "last release more than sixty days old"
		} else if time.Since(tr.LastRelease.GetCreatedAt().Time).Hours() > thirtyDays {
			return "warning", "last release more than thirty days old"
		}
	}

	return "", ""
}

func TargetRepo(org string, name string, configurers ...repoConfigurer) *targetRepo {
	t := &targetRepo{
		OrgName:  org,
		RepoName: name,

		HasGovulncheck: true,
		HasReleases:    true,

		GovulncheckWorkflowName: "govulncheck.yaml",
	}

	for _, c := range configurers {
		c(t)
	}

	return t
}

type DashboardHandler struct {
	indexTemplate *template.Template

	indexData     []byte
	indexDataLock sync.RWMutex
}

func NewDashboardHandler() (*DashboardHandler, error) {
	tmpl := template.New("index.html")
	tmpl = tmpl.Option("missingkey=error")

	var err error
	tmpl, err = tmpl.Parse(indexTemplateRaw)
	if err != nil {
		return nil, err
	}

	return &DashboardHandler{
		indexTemplate: tmpl,

		indexData:     []byte{},
		indexDataLock: sync.RWMutex{},
	}, nil
}

func (dh *DashboardHandler) Update(ctx context.Context) error {
	dh.indexDataLock.Lock()
	defer dh.indexDataLock.Unlock()

	buf := &bytes.Buffer{}

	data := struct {
		LastUpdated string
		Repos       []*targetRepo
	}{
		LastUpdated: time.Now().UTC().Format(time.DateTime),
		Repos:       targetList,
	}

	slices.SortFunc(data.Repos, func(a, b *targetRepo) int {
		if !a.HasReleases && !b.HasReleases {
			return 0
		}

		if a.HasReleases && !b.HasReleases {
			return -1
		} else if !a.HasReleases && b.HasReleases {
			return 1
		}

		return a.LastRelease.GetCreatedAt().Time.Compare(b.LastRelease.GetCreatedAt().Time)
	})

	err := dh.indexTemplate.Execute(buf, data)
	if err != nil {
		return err
	}

	dh.indexData = buf.Bytes()

	var warnings []string

	for _, repo := range targetList {
		_, warningMessage := repo.warnings()

		if warningMessage != "" {
			warnings = append(warnings, fmt.Sprintf("%s: %s", repo.RepoName, warningMessage))
		}
	}

	if len(warnings) > 0 {
		logger := logging.FromContext(ctx)

		message := strings.Join(warnings, ", ")

		if message != lastNtfy {
			err = ntfy(ntfyTopic, message)
			if err != nil {
				logger.Error("got an error trying to publish to ntfy.sh", "err", err)
			}

			lastNtfy = message
		} else {
			logger.Info("skipping publishing to ntfy.sh as message is unchanged")
		}
	}

	return nil
}

func (dh *DashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if path != "/" && path != "/index.html" && path != "/index.htm" {
		http.NotFoundHandler().ServeHTTP(w, r)
		return
	}

	dh.indexDataLock.RLock()
	defer dh.indexDataLock.RUnlock()

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dh.indexData)
}

func lastWeek() string {
	t := time.Now().Add(-1 * time.Hour * 24 * 7)

	return ">" + t.Format(time.DateOnly)

}

type repoFunc func(context.Context, *github.Client, *targetRepo) error

func forEachRepo(ctx context.Context, client *github.Client, f repoFunc) error {
	wg, ctx := errgroup.WithContext(ctx)

	for _, repo := range targetList {
		wg.Go(func() error {
			return f(ctx, client, repo)
		})
	}

	return wg.Wait()
}

func getLatestRunResult(ctx context.Context, client *github.Client, repo *targetRepo) error {
	if !repo.HasGovulncheck {
		return nil
	}

	listOpts := &github.ListWorkflowRunsOptions{
		Created: lastWeek(),
		ListOptions: github.ListOptions{
			PerPage: 25,
		},
	}

	runs, _, err := client.Actions.ListWorkflowRunsByFileName(ctx, repo.OrgName, repo.RepoName, repo.GovulncheckWorkflowName, listOpts)
	if err != nil {
		return err
	}

	for _, run := range runs.WorkflowRuns {
		if run.GetStatus() != "completed" {
			continue
		}

		repo.LastRun = run
		break
	}

	return nil
}

func getLatestRelease(ctx context.Context, client *github.Client, repo *targetRepo) error {
	if !repo.HasReleases {
		return nil
	}

	listOpts := &github.ListOptions{
		PerPage: 25,
	}

	releases, _, err := client.Repositories.ListReleases(ctx, repo.OrgName, repo.RepoName, listOpts)
	if err != nil {
		return err
	}

	if len(releases) == 0 {
		return fmt.Errorf("no releases found for %s/%s", repo.OrgName, repo.RepoName)
	}

	// set the first release in the GitHub response as the last release;
	// we might change this if there's a version filter set but at least this will return something sensible
	// if the version filter doesn't match anything
	repo.LastRelease = releases[0]

	if repo.VersionFilter == "" {
		// just use the first release and return
		return nil
	}

	foundMatch := false
	logger := logging.FromContext(ctx).With("repo", fmt.Sprintf("%s/%s", repo.OrgName, repo.RepoName), "versionFilter", repo.VersionFilter)

	for _, rel := range releases {
		tag := rel.GetTagName()

		match, err := regexp.MatchString(repo.VersionFilter, tag)
		if err != nil {
			logger.Error("failed to match version filter", "err", err, "tag", tag)
			continue
		}

		if match {
			repo.LastRelease = rel
			foundMatch = true
			break
		}
	}

	if !foundMatch {
		logger.Info("didn't find a matching release for version filter, will use latest")
	}

	return nil
}

func updateRepos(ctx context.Context, logger *slog.Logger, client *github.Client) error {
	wg, ctx := errgroup.WithContext(ctx)

	wg.Go(func() error {
		return forEachRepo(ctx, client, getLatestRelease)
	})

	wg.Go(func() error {
		return forEachRepo(ctx, client, getLatestRunResult)
	})

	return wg.Wait()
}

func maintainRepos(ctx context.Context, client *github.Client, dh *DashboardHandler) {
	logger := logging.FromContext(ctx).With("source", "repoMaintainer")

	ticker := time.NewTicker(maintainencePeriod)

	logger.Info("starting repo maintainer", "interval", maintainencePeriod.String())

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			logger.Info("updating repos", "nextRun", time.Now().Add(maintainencePeriod))
			err := updateRepos(ctx, logger, client)
			if err != nil {
				logger.Error("failed to update repos; data may be stale", "err", err)
				continue
			}

			err = dh.Update(ctx)
			if err != nil {
				logger.Error("failed to update dashboard handler; data may be stale", "err", err)
				continue
			}

		}
	}
}

func staticResourceHandler(w http.ResponseWriter, r *http.Request) {
	// This is very basic, and something like http.FileServerFS might work here, but we probably
	// won't need a tonne of static resources for this simple dashboard and there's little point
	// complicating things.
	switch r.URL.Path {
	case "/robots.txt":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write(robotsTXTData)
		return

	case "/favicon.ico":
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write(faviconData)
		return

	case "/css/bootstrap-v3.4.1.min.css":
		w.Header().Set("content-Type", "text/css")
		_, _ = w.Write(bootstrapV341CSSData)
		return

	default:
		http.NotFoundHandler().ServeHTTP(w, r)
	}
}

// This function taken from a MIT-licensed project from github.com/SgtCoDFish
func ntfy(topic string, warnings string) error {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	ntfyMessage := fmt.Sprintf("got warnings on at least one project: %s", warnings)

	path, err := url.JoinPath("https://ntfy.sh/", topic)
	if err != nil {
		return err
	}

	_, err = client.Post(path, "text/plain", strings.NewReader(ntfyMessage))
	return err
}

func addSecurityHeaders(setHSTS bool, underlying http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none';")
		if setHSTS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		}

		underlying.ServeHTTP(w, r)
	})
}

func run(ctx context.Context) error {
	ctx, done := signal.NotifyContext(ctx, os.Interrupt, os.Kill)
	defer done()

	logger := logging.FromContext(ctx)

	config := struct {
		GitHubToken string `json:"githubToken"`
	}{}

	configData, err := os.ReadFile("/etc/cert-manager-dashboard/config.json")
	if err != nil {
		token := os.Getenv("CERT_MANAGER_DASHBOARD_GITHUB_TOKEN")
		if token == "" {
			token := os.Getenv("GITHUB_TOKEN")
			if token == "" {
				return fmt.Errorf("no config.json available and no CERT_MANAGER_DASHBOARD_GITHUB_TOKEN/GITHUB_TOKEN found in env")
			}
		}

		config.GitHubToken = token
	} else {
		err = json.Unmarshal(configData, &config)
		if err != nil {
			return fmt.Errorf("couldn't parse config file: %s", err)
		}
	}

	if config.GitHubToken == "" {
		return fmt.Errorf("no GitHub token available")
	}

	client := github.NewClient(&http.Client{Timeout: 5 * time.Second}).WithAuthToken(config.GitHubToken)

	dashboardHandler, err := NewDashboardHandler()
	if err != nil {
		return err
	}

	err = updateRepos(ctx, logger.With("source", "initialScan"), client)
	if err != nil {
		return fmt.Errorf("failed to complete initial sync for repo data: %s", err)
	}

	err = dashboardHandler.Update(ctx)
	if err != nil {
		return err
	}

	go maintainRepos(ctx, client, dashboardHandler)

	mux := http.NewServeMux()

	mux.Handle("GET /", dashboardHandler)

	mux.HandleFunc("GET /favicon.ico", staticResourceHandler)
	mux.HandleFunc("GET /robots.txt", staticResourceHandler)
	mux.HandleFunc("GET /css/bootstrap-v3.4.1.min.css", staticResourceHandler)

	addr := "[::1]:49984"
	setHSTS := true

	server := &http.Server{
		Addr:        addr,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
		ErrorLog:    slog.NewLogLogger(logger.With("source", "httpServer").Handler(), slog.LevelError),
		Handler:     addSecurityHeaders(setHSTS, mux),
	}

	go func() {
		err := server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			logger.Error("failed to listen with server", "err", err)
		}
	}()

	logger.Info("server listening", "addr", addr)

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	err = server.Shutdown(shutdownCtx)
	if err != nil {
		cancel()
		return err
	}

	cancel()

	<-shutdownCtx.Done()

	return nil
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	ctx := logging.NewContext(context.Background(), logger)

	err := run(ctx)
	if err != nil {
		logger.Error("failed to execute", "err", err)
		os.Exit(1)
	}
}
