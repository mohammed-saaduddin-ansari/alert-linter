package lint

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"

	"github.com/mohammed-saaduddin-ansari/alert-linter/internal/config"
	"github.com/mohammed-saaduddin-ansari/alert-linter/internal/loader"
)

// Check is one lint rule.
type Check struct {
	ID      string
	Summary string
	// Why explains the on-call impact; it is shown by --list-rules and as
	// the help text in SARIF, so code-scanning reviewers see it inline.
	Why     string
	Default Severity
	// Records is true if the check also runs on recording rules.
	Records bool
	run     func(*target) []issue
}

type issue struct {
	pos  loader.Pos
	sev  Severity // Unset means the check's default
	msg  string
	hint string
}

// target is a rule plus everything derived from it once, up front.
type target struct {
	*loader.Rule
	cfg         *config.Config
	expr        parser.Expr
	parseErr    error
	severity    string
	hasSeverity bool
	paging      bool
}

var (
	checkInvalidRule = &Check{
		ID:      "invalid-rule",
		Summary: "Rule file or rule cannot be parsed",
		Why: "A rule that Prometheus cannot load never fires. Broken YAML or PromQL usually " +
			"means a whole group is silently missing until someone notices the gap during an incident.",
		Default: Error,
		Records: true,
	}
	checkUnknownDirective = &Check{
		ID:      "unknown-directive",
		Summary: "Inline directive names a rule that does not exist",
		Why: "A misspelt disable comment does nothing, so the finding it was meant to silence " +
			"keeps failing CI and people learn to ignore the linter.",
		Default: Warning,
	}
	checkDuplicate = &Check{
		ID:      "duplicate-alert",
		Summary: "Same alert name and identical labels defined twice",
		Why: "Two definitions with the same identity look like one alert to Alertmanager. " +
			"Silences, inhibitions and grouping hit both, and responders see duplicate or " +
			"flip-flopping notifications for what is really a copy-paste mistake.",
		Default: Error,
	}
)

// Checks is the registry, in the order they are documented.
var Checks = []*Check{
	checkInvalidRule,
	{
		ID:      "paging-missing-for",
		Summary: "Paging alert has no `for:` duration",
		Why: "Without `for:` the alert fires on the first evaluation where the expression is true. " +
			"One slow scrape, a restart or a deploy blip is enough to wake someone, and the alert " +
			"resolves before they open a laptop. Requiring the condition to persist is the cheapest " +
			"way to remove pages nobody can act on.",
		Default: Error,
		run:     runPagingMissingFor,
	},
	{
		ID:      "short-for",
		Summary: "`for:` is shorter than the configured minimum",
		Why: "A `for:` shorter than an evaluation interval or two barely debounces anything: the " +
			"alert flaps between firing and resolved, each flap can notify, and responders learn " +
			"that the alert is noise.",
		Default: Warning,
		run:     runShortFor,
	},
	{
		ID:      "missing-runbook-url",
		Summary: "No `runbook_url` annotation (or it is not a URL)",
		Why: "At 03:00 the responder needs to know what to check first and how to mitigate. A " +
			"runbook link turns a page into a procedure and is the difference between a five-minute " +
			"and a fifty-minute response. Error on paging alerts, warning otherwise.",
		Default: Error,
		run:     runMissingRunbook,
	},
	{
		ID:      "missing-summary",
		Summary: "No `summary` annotation",
		Why: "The summary is the notification title in most pagers and chat tools. Without it the " +
			"responder sees only an alert name and must open a dashboard to learn what is wrong " +
			"and where. Error on paging alerts, warning otherwise.",
		Default: Error,
		run:     annotationCheck("summary", "a one-line, templated summary such as `{{ $labels.job }} is serving 5xx to {{ $value | humanizePercentage }} of requests`"),
	},
	{
		ID:      "missing-description",
		Summary: "No `description` annotation",
		Why: "The description carries the context a summary cannot: what the threshold means, " +
			"user impact and the likely blast radius. It helps the responder decide quickly " +
			"whether to escalate.",
		Default: Warning,
		run:     annotationCheck("description", "a few sentences on impact and what the threshold means"),
	},
	{
		ID:      "missing-severity",
		Summary: "No severity label",
		Why: "Routing decides who gets woken up from the severity label. An alert without one either " +
			"falls through to a default receiver nobody watches or pages by accident.",
		Default: Error,
		run:     runMissingSeverity,
	},
	{
		ID:      "unknown-severity",
		Summary: "Severity value is not in the allowed list",
		Why: "Values such as `crit`, `P1` or `High` slip past Alertmanager routes that match on " +
			"exact values, so the alert silently goes to the wrong place or nowhere.",
		Default: Error,
		run:     runUnknownSeverity,
	},
	{
		ID:      "missing-owner-label",
		Summary: "No team/owner label",
		Why: "An alert without an owner pages whoever holds the default route. Ownership labels let " +
			"routing reach the team that can actually fix the problem and make alert-quality " +
			"reviews possible per team.",
		Default: Warning,
		run:     runMissingOwner,
	},
	{
		ID:      "cause-based-paging",
		Summary: "Paging alert fires on a resource cause (CPU, memory, disk)",
		Why: "High CPU or memory is a cause, not a symptom: plenty of healthy systems run hot, and " +
			"plenty of outages happen at 20% CPU. Paging on causes produces pages with no user " +
			"impact and misses outages that do have it. Page on symptoms users feel (errors, " +
			"latency, SLO burn rate) and send causes to a ticket or dashboard.",
		Default: Warning,
		run:     runCauseBasedPaging,
	},
	{
		ID:      "rate-window-too-short",
		Summary: "rate()/increase() window shorter than N x scrape interval",
		Why: "rate() needs at least two samples inside its window. With a window under about four " +
			"scrape intervals, one missed or late scrape leaves too few samples, the expression " +
			"returns nothing and the alert cannot fire, exactly when the target is struggling.",
		Default: Error,
		Records: true,
		run:     runRateWindow,
	},
	{
		ID:      "high-cardinality-grouping",
		Summary: "Paging alert aggregates by a high-cardinality label",
		Why: "`sum by (pod)` on a paging alert turns one incident into one page per pod. A bad " +
			"rollout across 40 pods should be one page with 40 pods in the description, not 40 " +
			"pages. Warning only, because some per-instance pages are deliberate.",
		Default: Warning,
		run:     runHighCardinality,
	},
	checkDuplicate,
	checkUnknownDirective,
}

// CheckByID looks up a check.
func CheckByID(id string) *Check {
	for _, c := range Checks {
		if c.ID == id {
			return c
		}
	}
	return nil
}

func (t *target) isAlert() bool { return t.Kind == loader.Alert }

func (t *target) pagingNote() string {
	return fmt.Sprintf("%s=%s", t.cfg.SeverityLabel, t.severity)
}

func dur(d time.Duration) string { return model.Duration(d).String() }

func runPagingMissingFor(t *target) []issue {
	if !t.isAlert() || !t.paging || (t.HasFor && t.For > 0) {
		return nil
	}
	hint := "add `for: 5m` (or whatever the condition needs to be meaningful) so it must persist before anyone is woken"
	if t.HasFor {
		return []issue{{pos: t.ForPos, msg: fmt.Sprintf("paging alert %q (%s) has `for: 0s`, so one bad evaluation pages someone", t.Name, t.pagingNote()), hint: hint}}
	}
	return []issue{{pos: t.NamePos, msg: fmt.Sprintf("paging alert %q (%s) has no `for:`, so one bad evaluation pages someone", t.Name, t.pagingNote()), hint: hint}}
}

func runShortFor(t *target) []issue {
	if !t.isAlert() || !t.HasFor || t.For <= 0 || t.For >= t.cfg.MinFor {
		return nil
	}
	return []issue{{
		pos:  t.ForPos,
		msg:  fmt.Sprintf("alert %q has `for: %s`, shorter than the %s minimum, so brief blips will fire and resolve repeatedly", t.Name, dur(t.For), dur(t.cfg.MinFor)),
		hint: fmt.Sprintf("raise `for:` to at least %s, or lower min_for in the config if this really must be fast", dur(t.cfg.MinFor)),
	}}
}

// sevForPaging returns Error for paging alerts and Warning for others.
func (t *target) sevForPaging() Severity {
	if t.paging {
		return Error
	}
	return Warning
}

func (t *target) kindNote() string {
	if t.paging {
		return "paging alert"
	}
	return "alert"
}

func runMissingRunbook(t *target) []issue {
	if !t.isAlert() {
		return nil
	}
	v, ok := t.Annotations["runbook_url"]
	if !ok || strings.TrimSpace(v) == "" {
		return []issue{{
			pos:  t.AnnotationsPos,
			sev:  t.sevForPaging(),
			msg:  fmt.Sprintf("%s %q has no runbook_url annotation", t.kindNote(), t.Name),
			hint: "link a runbook that says what to check first and how to mitigate",
		}}
	}
	if !strings.Contains(v, "{{") && !strings.HasPrefix(v, "https://") && !strings.HasPrefix(v, "http://") {
		return []issue{{
			pos:  t.AnnotationPos["runbook_url"],
			sev:  Warning,
			msg:  fmt.Sprintf("alert %q has runbook_url %q, which is not an absolute http(s) URL", t.Name, v),
			hint: "use a full URL so it is clickable from the pager and chat notification",
		}}
	}
	return nil
}

func annotationCheck(key, example string) func(*target) []issue {
	return func(t *target) []issue {
		if !t.isAlert() || strings.TrimSpace(t.Annotations[key]) != "" {
			return nil
		}
		sev := Warning
		if key == "summary" {
			sev = t.sevForPaging()
		}
		return []issue{{
			pos:  t.AnnotationsPos,
			sev:  sev,
			msg:  fmt.Sprintf("%s %q has no %s annotation", t.kindNote(), t.Name, key),
			hint: "add " + example,
		}}
	}
}

func runMissingSeverity(t *target) []issue {
	if !t.isAlert() || t.hasSeverity {
		return nil
	}
	return []issue{{
		pos:  t.LabelsPos,
		msg:  fmt.Sprintf("alert %q has no %s label, so routing cannot tell whether it should page", t.Name, t.cfg.SeverityLabel),
		hint: fmt.Sprintf("add `%s:` with one of: %s", t.cfg.SeverityLabel, strings.Join(t.cfg.AllowedSeverities, ", ")),
	}}
}

func runUnknownSeverity(t *target) []issue {
	if !t.isAlert() || !t.hasSeverity || strings.Contains(t.severity, "{{") || t.cfg.IsAllowedSeverity(t.severity) {
		return nil
	}
	return []issue{{
		pos:  t.LabelPos[t.cfg.SeverityLabel],
		msg:  fmt.Sprintf("alert %q has %s %q, which routing does not know about", t.Name, t.cfg.SeverityLabel, t.severity),
		hint: "use one of: " + strings.Join(t.cfg.AllowedSeverities, ", "),
	}}
}

func runMissingOwner(t *target) []issue {
	if !t.isAlert() {
		return nil
	}
	for _, l := range t.cfg.OwnerLabels {
		if strings.TrimSpace(t.Labels[l]) != "" {
			return nil
		}
	}
	return []issue{{
		pos:  t.LabelsPos,
		msg:  fmt.Sprintf("alert %q has no owner label (%s)", t.Name, strings.Join(t.cfg.OwnerLabels, " or ")),
		hint: "add a team label on the rule or once on the rule group's `labels:` so routing reaches the people who can fix it",
	}}
}

// metricNames returns the metric names an expression selects, in order.
func metricNames(e parser.Expr) []string {
	var out []string
	parser.Inspect(e, func(n parser.Node, _ []parser.Node) error {
		vs, ok := n.(*parser.VectorSelector)
		if !ok {
			return nil
		}
		name := vs.Name
		if name == "" {
			for _, m := range vs.LabelMatchers {
				if m.Name == model.MetricNameLabel && m.Type == labels.MatchEqual {
					name = m.Value
				}
			}
		}
		if name != "" && !slices.Contains(out, name) {
			out = append(out, name)
		}
		return nil
	})
	return out
}

func usesFunction(e parser.Expr, fn string) bool {
	found := false
	parser.Inspect(e, func(n parser.Node, _ []parser.Node) error {
		if c, ok := n.(*parser.Call); ok && c.Func.Name == fn {
			found = true
		}
		return nil
	})
	return found
}

func runCauseBasedPaging(t *target) []issue {
	if !t.paging || t.expr == nil {
		return nil
	}
	// predict_linear on a filesystem ("disk full in 4h") is a classic,
	// legitimate page: the user-facing outage is imminent and certain.
	if usesFunction(t.expr, "predict_linear") {
		return nil
	}
	var causes []string
	for _, name := range metricNames(t.expr) {
		for _, re := range t.cfg.CauseMetrics {
			if re.MatchString(name) {
				causes = append(causes, name)
				break
			}
		}
	}
	if len(causes) == 0 {
		return nil
	}
	return []issue{{
		pos: t.ExprPos,
		msg: fmt.Sprintf("paging alert %q (%s) fires on a resource cause (%s) rather than a symptom users feel",
			t.Name, t.pagingNote(), strings.Join(causes, ", ")),
		hint: "page on error rate, latency or SLO burn rate and send this one to a ticket (e.g. severity: warning); " +
			"for disks, a predict_linear() time-to-full alert is a reasonable page",
	}}
}

var rateFunctions = map[string]bool{
	"rate": true, "irate": true, "increase": true,
	"delta": true, "idelta": true, "deriv": true,
}

func runRateWindow(t *target) []issue {
	if t.expr == nil {
		return nil
	}
	factor := time.Duration(t.cfg.RateWindowFactor)
	minWindow := factor * t.cfg.ScrapeInterval
	var short, subqueries []string
	parser.Inspect(t.expr, func(n parser.Node, _ []parser.Node) error {
		call, ok := n.(*parser.Call)
		if !ok || !rateFunctions[call.Func.Name] || len(call.Args) == 0 {
			return nil
		}
		switch arg := call.Args[0].(type) {
		case *parser.MatrixSelector:
			// Range is 0 for experimental duration expressions; skip those.
			if arg.Range > 0 && arg.Range < minWindow {
				s := fmt.Sprintf("%s(%s)", call.Func.Name, arg.String())
				if !slices.Contains(short, s) {
					short = append(short, s)
				}
			}
		case *parser.SubqueryExpr:
			if arg.Step > 0 && arg.Range < factor*arg.Step {
				s := fmt.Sprintf("%s(%s)", call.Func.Name, arg.String())
				if !slices.Contains(subqueries, s) {
					subqueries = append(subqueries, s)
				}
			}
		}
		return nil
	})
	var out []issue
	if len(short) > 0 {
		out = append(out, issue{
			pos: t.ExprPos,
			msg: fmt.Sprintf("%q: %s %s shorter than %d x the %s scrape interval (%s); one missed scrape leaves too few samples and the expression returns nothing",
				t.Name, strings.Join(short, ", "), pick(len(short) == 1, "uses a window", "use windows"),
				t.cfg.RateWindowFactor, dur(t.cfg.ScrapeInterval), dur(minWindow)),
			hint: fmt.Sprintf("use a window of at least %s, or set scrape_interval in the config if your targets are scraped faster", dur(minWindow)),
		})
	}
	if len(subqueries) > 0 {
		out = append(out, issue{
			pos: t.ExprPos,
			msg: fmt.Sprintf("%q: %s %s fewer than %d subquery steps, too few points for a stable rate",
				t.Name, strings.Join(subqueries, ", "), pick(len(subqueries) == 1, "covers", "cover"), t.cfg.RateWindowFactor),
			hint: fmt.Sprintf("make the subquery range at least %d x its step", t.cfg.RateWindowFactor),
		})
	}
	return out
}

func pick(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

func runHighCardinality(t *target) []issue {
	if !t.paging || t.expr == nil {
		return nil
	}
	var hits []string
	parser.Inspect(t.expr, func(n parser.Node, _ []parser.Node) error {
		agg, ok := n.(*parser.AggregateExpr)
		if !ok || agg.Without {
			return nil
		}
		for _, g := range agg.Grouping {
			if slices.Contains(t.cfg.HighCardinalityLabels, g) && !slices.Contains(hits, g) {
				hits = append(hits, g)
			}
		}
		return nil
	})
	if len(hits) == 0 {
		return nil
	}
	return []issue{{
		pos: t.ExprPos,
		msg: fmt.Sprintf("paging alert %q aggregates by (%s), so one incident fans out into one page per %s",
			t.Name, strings.Join(hits, ", "), hits[0]),
		hint: "page at the service level (e.g. `sum by (namespace, job)`) and list affected " + hits[0] + "s in the description or dashboard",
	}}
}
