package scanner

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"time"

	"octoscan/common"

	"github.com/fatih/color"
	"github.com/mattn/go-colorable"
	"github.com/rhysd/actionlint"
)

// ColorOptionKind is kind of colorful output behavior.
type ColorOptionKind int

const (
	// ColorOptionKindAuto is kind to determine to colorize errors output automatically. It is
	// determined based on pty and $NO_COLOR environment variable. See document of fatih/color
	// for more details.
	ColorOptionKindAuto ColorOptionKind = iota
	// ColorOptionKindAlways is kind to always colorize errors output.
	ColorOptionKindAlways
	// ColorOptionKindNever is kind never to colorize errors output.
	ColorOptionKindNever
)

// ScannerOptions is set of options for Scanner instance. This struct should be created by user and
// given to NewScanner factory function.
type ScannerOptions struct {
	// Verbose is flag if verbose log output is enabled.
	Verbose bool
	// Color is option for colorizing error outputs. See ColorOptionKind document for each enum values.
	Color ColorOptionKind
	// Oneline is flag if one line output is enabled. When enabling it, one error is output per one
	// line. It is useful when reading outputs from programs.
	Oneline bool
	// Shellcheck is executable for running shellcheck external command. It can be command name like
	// "shellcheck" or file path like "/path/to/shellcheck", "path/to/shellcheck". When this value
	// is empty, shellcheck won't run to check scripts in workflow file.
	Shellcheck string
	// IgnorePatterns is list of regular expression to filter errors. The pattern is applied to error
	// messages. When an error is matched, the error is ignored.
	IgnorePatterns []string
	// Format is a custom template to format error messages. It must follow Go Template format and
	// contain at least one {{ }} placeholder. https://pkg.go.dev/text/template
	Format string
	// StdinFileName is a file name when reading input from stdin. When this value is empty, "<stdin>"
	// is used as the default value.
	StdinFileName string
	// WorkingDir is a file path to the current working directory. When this value is empty, os.Getwd
	// will be used to get a working directory.
	WorkingDir string
	// More options will come here
}

// Scanner is struct to scan workflow files.
type Scanner struct {
	projects   *actionlint.Projects
	out        io.Writer
	oneline    bool
	shellcheck string
	ignorePats []*regexp.Regexp
	errFmt     *actionlint.ErrorFormatter
	cwd        string
}

// NewScanner creates a new Scanner instance.
// The out parameter is used to output errors from Linter instance. Set io.Discard if you don't
// want the outputs.
// The opts parameter is ScannerOptions instance which configures behavior of scanning.
func NewScanner(out io.Writer, opts *ScannerOptions) (*Scanner, error) {

	if opts.Color == ColorOptionKindNever {
		color.NoColor = true
	} else {
		if opts.Color == ColorOptionKindAlways {
			color.NoColor = false
		}
		// Allow colorful output on Windows
		if f, ok := out.(*os.File); ok {
			out = colorable.NewColorable(f)
		}
	}

	ignore := make([]*regexp.Regexp, 0, len(opts.IgnorePatterns))
	for _, s := range opts.IgnorePatterns {
		r, err := regexp.Compile(s)
		if err != nil {
			return nil, fmt.Errorf("invalid regular expression for ignore pattern %q: %s", s, err.Error())
		}
		ignore = append(ignore, r)
	}

	var formatter *actionlint.ErrorFormatter
	if opts.Format != "" {
		f, err := actionlint.NewErrorFormatter(opts.Format)
		if err != nil {
			return nil, err
		}
		formatter = f
	}

	cwd := opts.WorkingDir
	if cwd == "" {
		if d, err := os.Getwd(); err == nil {
			cwd = d
		}
	}

	return &Scanner{
		actionlint.NewProjects(),
		out,
		opts.Oneline,
		opts.Shellcheck,
		ignore,
		formatter,
		cwd,
	}, nil
}

// ScanFile scan one YAML workflow file and outputs the errors to given writer. The project
// parameter can be nil. In the case, the project is detected from the given path.
func (l *Scanner) ScanFile(path string, project *actionlint.Project) ([]*actionlint.Error, error) {
	if project == nil {
		project = l.projects.At(path)
	}

	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read %q: %w", path, err)
	}

	if l.cwd != "" {
		if r, err := filepath.Rel(l.cwd, path); err == nil {
			path = r
		}
	}

	proc := newConcurrentProcess(runtime.NumCPU())
	dbg := common.Log.DebugWriter()
	localActions := actionlint.NewLocalActionsCache(project, dbg)
	localReusableWorkflows := actionlint.NewLocalReusableWorkflowCache(project, l.cwd, dbg)
	errs, err := l.check(path, src, project, proc, localActions, localReusableWorkflows)
	proc.wait()
	if err != nil {
		return nil, err
	}

	if l.errFmt != nil {
		l.errFmt.PrintErrors(l.out, errs, src)
	} else {
		l.printErrors(errs, src)
	}
	return errs, err
}

func (l *Scanner) check(
	path string,
	content []byte,
	project *actionlint.Project,
	proc *concurrentProcess,
	localActions *actionlint.LocalActionsCache,
	localReusableWorkflows *actionlint.LocalReusableWorkflowCache,
) ([]*actionlint.Error, error) {
	// Note: This method is called to check multiple files in parallel.
	// It must be thread safe assuming fields of Linter are not modified while running.

	start := time.Now()

	common.Log.Verbose("Scanning", path)
	if project != nil {
		common.Log.Verbose("Using project at", project.RootDir())
	}

	w, all := actionlint.Parse(content)

	elapsed := time.Since(start)
	common.Log.Verbose("Found", len(all), "parse errors in", elapsed.Milliseconds(), "ms for", path)

	if w != nil {
		dbg := common.Log.DebugWriter()

		rules := []actionlint.Rule{
			actionlint.NewRuleCredentials(),
		}

		//TODO: shellcheck

		v := actionlint.NewVisitor()
		for _, rule := range rules {
			v.AddPass(rule)
		}
		if dbg != nil {
			v.EnableDebug(dbg)
			for _, r := range rules {
				r.EnableDebug(dbg)
			}
		}

		if err := v.Visit(w); err != nil {
			common.Log.Debug(fmt.Sprintf("error occurred while visiting workflow syntax tree: %v", err))
			return nil, err
		}

		for _, rule := range rules {
			errs := rule.Errs()
			common.Log.Debug(fmt.Sprintf("%s found %d errors", rule.Name(), len(errs)))
			all = append(all, errs...)
		}

		// TODO
		//if l.errFmt != nil {
		//	for _, rule := range rules {
		//		l.errFmt.RegisterRule(rule)
		//	}
		//}
	}

	if len(l.ignorePats) > 0 {
		filtered := make([]*actionlint.Error, 0, len(all))
	Loop:
		for _, err := range all {
			for _, pat := range l.ignorePats {
				if pat.MatchString(err.Message) {
					continue Loop
				}
			}
			filtered = append(filtered, err)
		}
		all = filtered
	}

	for _, err := range all {
		err.Filepath = path // Populate filename in the error
	}

	sort.Stable(actionlint.ByErrorPosition(all))

	elapsed = time.Since(start)
	common.Log.Verbose("Found total", len(all), "errors in", elapsed.Milliseconds(), "ms for", path)

	return all, nil
}

func (l *Scanner) printErrors(errs []*actionlint.Error, src []byte) {
	if l.oneline {
		src = nil
	}
	for _, err := range errs {
		err.PrettyPrint(l.out, src)
	}
}
