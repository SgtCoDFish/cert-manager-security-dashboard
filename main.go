package main

import (
	"bytes"
	"context"
	"embed"
	_ "embed"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
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
)

var (
	// targetList is the list of repos we want to check
	targetList = []*targetRepo{
		TargetRepo("cert-manager", "cert-manager"),
		TargetRepo("cert-manager", "trust-manager"),
		TargetRepo("cert-manager", "approver-policy"),
		TargetRepo("cert-manager", "csi-driver"),
		TargetRepo("cert-manager", "csi-driver-spiffe"),
		TargetRepo("cert-manager", "istio-csr"),
		TargetRepo("cert-manager", "cmctl"),
		TargetRepo("cert-manager", "google-cas-issuer"),
		TargetRepo("cert-manager", "openshift-routes"),
	}

	//go:embed templates/index.html
	indexTemplateRaw string

	//go:embed static/robots.txt
	robotsTXTData []byte

	//go:embed static/favicon.ico
	faviconData []byte

	//go:embed static/css/bootstrap.min.css
	bootstrapCSSData []byte

	//go:embed static
	staticFS embed.FS
)

type targetRepo struct {
	OrgName  string
	RepoName string

	HasGovulncheck bool
	HasReleases    bool

	GovulncheckWorkflowName string

	LastRun *github.WorkflowRun

	LastRelease *github.RepositoryRelease
}

func (tr *targetRepo) BootstrapClass() string {
	cls, _ := tr.warnings()
	return cls
}

func (tr *targetRepo) WarningMessage() string {
	_, wrn := tr.warnings()
	return wrn
}

func (tr *targetRepo) LastReleaseTime() string {
	if !tr.HasReleases || tr.LastRelease == nil {
		return "N/A"
	}

	return tr.LastRelease.GetCreatedAt().Time.UTC().Format(time.DateTime)
}

func (tr *targetRepo) LastGovulncheckTime() string {
	if !tr.HasGovulncheck || tr.LastRun == nil {
		return "N/A"
	}

	return tr.LastRun.GetCreatedAt().Time.UTC().Format(time.DateTime)
}

// warnings returns a bootstrap class[1] and a reason if there are any
// warnings which should be shown for this repo. Can return empty strings
// if no warnings are needed.
// [1] https://getbootstrap.com/docs/3.4/css/#tables-contextual-classes
func (tr *targetRepo) warnings() (string, string) {
	if tr.HasGovulncheck {
		if tr.LastRun == nil {
			return "danger", "no data for last run"
		} else if tr.LastRun.GetConclusion() != "success" {
			return "warning", "last run not successful"
		} else if time.Since(tr.LastRun.GetCreatedAt().Time).Hours() > twoDays {
			return "warning", "govulncheck stale for more than two days"
		}
	}

	if tr.HasReleases {
		if tr.LastRelease == nil {
			return "danger", "no data for last release"
		}

		if time.Since(tr.LastRelease.GetCreatedAt().Time).Hours() > thirtyDays {
			return "warning", "last release more than thirty days old"
		}
	}

	return "", ""
}

func TargetRepo(org string, name string) *targetRepo {
	return &targetRepo{
		OrgName:  org,
		RepoName: name,

		HasGovulncheck: true,
		HasReleases:    true,

		GovulncheckWorkflowName: "govulncheck.yaml",
	}
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

func (dh *DashboardHandler) Update() error {
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

	err := dh.indexTemplate.Execute(buf, data)
	if err != nil {
		return err
	}

	dh.indexData = buf.Bytes()

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

	repo.LastRelease = releases[0]

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

func maintainRepos(ctx context.Context, client *github.Client, dh *DashboardHandler) error {
	logger := logging.FromContext(ctx).With("source", "repoMaintainer")

	ticker := time.NewTicker(maintainencePeriod)

	logger.Info("starting repo maintainer", "interval", maintainencePeriod.String())

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-ticker.C:
			logger.Info("updating repos", "nextRun", time.Now().Add(maintainencePeriod))
			err := updateRepos(ctx, logger, client)
			if err != nil {
				logger.Error("failed to update repos; data may be stale", "err", err)
				continue
			}

			err = dh.Update()
			if err != nil {
				logger.Error("failed to update dashboard handler; data may be stale", "err", err)
				continue
			}
		}
	}
}

func staticResourceHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/robots.txt":
		http.ServeFileFS(w, r, staticFS, "static/robots.txt")

	case "/favicon.ico":
		http.ServeFileFS(w, r, staticFS, "static/favicon.ico")

	case "/css/bootstrap.min.css":
		http.ServeFileFS(w, r, staticFS, "static/css/bootstrap.min.css")

	default:
		http.NotFoundHandler().ServeHTTP(w, r)
	}
}

func run(ctx context.Context) error {
	ctx, done := signal.NotifyContext(ctx, os.Interrupt, os.Kill)
	defer done()

	logger := logging.FromContext(ctx)

	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		return fmt.Errorf("no GITHUB_TOKEN found in env")
	}

	client := github.NewClient(&http.Client{Timeout: 5 * time.Second}).WithAuthToken(token)

	dashboardHandler, err := NewDashboardHandler()
	if err != nil {
		return err
	}

	err = updateRepos(ctx, logger.With("source", "initialScan"), client)
	if err != nil {
		return fmt.Errorf("failed to complete initial sync for repo data: %s", err)
	}

	err = dashboardHandler.Update()
	if err != nil {
		return err
	}

	go maintainRepos(ctx, client, dashboardHandler)

	mux := http.NewServeMux()

	mux.Handle("GET /", dashboardHandler)

	mux.HandleFunc("GET /favicon.ico", staticResourceHandler)
	mux.HandleFunc("GET /robots.txt", staticResourceHandler)
	mux.HandleFunc("GET /css/bootstrap.min.css", staticResourceHandler)

	addr := ":49984"
	server := &http.Server{
		Addr:        addr,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
		ErrorLog:    slog.NewLogLogger(logger.With("source", "httpServer").Handler(), slog.LevelError),
		Handler:     mux,
	}

	go func() {
		err := server.ListenAndServe()
		if err != http.ErrServerClosed {
			logger.Error("failed to listen with server", "err", err)
		}
	}()

	logger.Info("server listening", "addr", addr)

	<-ctx.Done()

	err = server.Shutdown(context.Background())
	if err != nil {
		return err
	}

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
