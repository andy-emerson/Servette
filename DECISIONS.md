# Decisions

The closed rulings: what was decided, what was rejected, and what would
reopen each. This file is the canonical in-repo record; the linked issues
hold the deliberation, and [`DESIGN.md`](DESIGN.md) describes what is
built as a result. Entries are compact and present-tense; newest first.
Only the Human closes a decision ([`AGENTS.md`](AGENTS.md)).

## A printed line earns its place only if the reader cannot already see it

**Ruled (Human):** one rule over every command's output, arrived at by
walking `enable` and `admin` line by line. A line stays if it tells the
reader something the surrounding lines, the labels, or the program's own
behaviour do not already say. It goes if it announces what the next line
names, restates what the line above stated, or reports a step the
operator can see happening.

Applied, with what each line was judged against:

- `'<cmd>' needs root; asking sudo.` — **gone.** sudo prompts when it
  wants a password and is silent when it does not, so the notice was
  either redundant or noise. The sudo-is-missing line stays: it is the
  only account of why nothing happened.
- `The admin page is up:` — **gone**, and `link` became `admin page`.
  Killing a header only works if the label carries the meaning; `link`
  named a protocol, not a destination.
- `admin`'s three pointer lines — **folded into the prompt**, which is
  where a reader looks when wondering what to type. Seven lines to four.
- `enable`'s watchdog line — **first enable only.** A refresh re-writes
  the unit and stops; the watchdog was armed by the first enable and is
  still armed, so on a re-run the line is not news.
- `restore-site`'s parenthetical explaining the version ring —
  **replaced** by one sentence saying when a kept version appears.
- `start`'s macOS line — **rewritten** to carry only what the line above
  does not: a permanent service needs Linux.

**Why (user pov):** the operator reads the terminal to find one thing;
every line that says nothing is a line between them and it. **(developer
pov):** a rule settles a family of these, where line-by-line taste
re-argues each one and drifts.
**Reviewed and left alone:** `disable`, `stop`, `status`, `log`,
`traffic`, `set`, `config` — one line per outcome, or structured output.
`setup` is a first-run walkthrough, where explaining is the job.
*(2026-08-24)*

## The publish sub-shell goes; its one verb keeps its own front door

**Ruled (Human):** the sub-shell existed to gather the content channel's
scattered verbs — `pull`, `restore-site`, `channel`. The pull channel's
removal left it wrapping a single verb that was already a top-level
command, so it is removed rather than kept as a menu of one.
`restore-site` is unchanged and still elevates.
**Why (user pov):** one door per job; a menu holding one item is a step
that teaches nothing. **(developer pov):** a wrapper with one call is
the shape a reader has to read twice to learn it does nothing.
**Went with it, not replaced:** the display that listed every site's
kept versions side by side (nothing shows that now — `restore-site`
lists one site's, and only when a rollback is available), and the one
line pointing at the browser page. Adding a command is not part of a
removal; either can come back if it is missed.
*(2026-08-24)*

## Command output is indented, without exception

**Ruled (Human):** a bug, not a style choice. Every line the shell prints
carries the same two-space indent; 38 lines across `enable`, `disable`,
`start`, `stop`, `log` and the certificate warnings did not, so one
command's output read as two programs talking.
**Left alone:** `status`'s own headline, which is a display with its own
layout rather than a line of command output. *(2026-08-24)*

## Everything that wants attention: counted once, marked once, where the fix is

**Ruled (Human).** One rule, no exceptions, applied to every state:

- **The Status line counts, and says nothing else.** `N to review`, or
  `✓ healthy`. It does not name its members — each is named on its own
  row, and four names here would be a sentence nobody reads. This is the
  only place a card can report itself *well*: every other row speaks for
  its own subject.
- **One mark per item, on the row that carries its fix.** Certificate on
  the certificate row. Login on the access row. A missing folder on the
  **Published** row, because publishing is what puts it back — it used to
  sit in the facts block, nowhere near anything that would fix it.
- **Nothing else.** No third register: no red paragraph restating what a
  row already says. Where a form cannot be saved, **Save is dim** and the
  row says what is missing — a refusal to print is the third register by
  another name.

**An unfinished edit is one of these items.** Flipping to private without
a login is counted and marked, so the card cannot say "healthy" beside a
form it is refusing. It was doing exactly that, which is the
inconsistency that made this ruling necessary.
**Severity by consequence, not by kind:** a stored username with no
password locks every visitor out — red. The same login half-typed has
changed nothing yet — amber. The row's words say which is missing ("a
username is needed" / "a password is needed"), not both at once.
**Verified across every state, in a browser**, because getting it right
for the certificate and wrong for the others is what happened three
times: nothing wrong, certificate, folder, login, and all three at once.
*(2026-08-24)*

**Ruled (Human):** two things, and only two.

1. **The Status line** — the count, naming what it counts, and the only
   place on the card that says the site is *well*. No other row can say
   that: they report their own subject, and a card with nothing wrong
   would otherwise say nothing at all.
2. **One mark per problem, on the row that carries its fix** — the
   certificate row for a certificate, the access row for a login. An
   indicator anywhere else is an indicator you have to go and find the fix
   for.

**The head pill is not a third thing.** It is the Status line for a folded
card: shown only while the body is hidden, so the count never vanishes
because a card is closed, and never doubles the line inside it.
**Refusals move to the control that refused**, for the same reason — the
login refusal belongs under Save, not at the foot of the card below Test
connection. So does explanatory text: the DNS note sat below the access
block explaining a certificate button three controls above it, and now
sits under that button.
**The Agent got this backwards once**, removing the count and keeping the
pill — optimising away the one indicator that carried information for the
two that repeated it. Recorded because the reasoning that produced it
("say it once, on the row that fixes it") was right and still led
somewhere wrong: the count is not a repetition of the rows, it is the
summary and the all-clear.
**Worth knowing about the count's set:** with the page as the only
surface, little but the certificate raises it today. A missing serve
folder can; a half-built pull channel can, but that is terminal-only; and
the half-authenticated state the access row reports is one the page's own
guard prevents reaching. *(2026-08-24)*

## The connection test does not report the version

**Ruled (Human):** the Version row is dropped. `/.well-known/servette`
stays — it is a published path and something outside Servette may use
it — but nothing in the product asks for it any more.
**Why:** on a public site the endpoint answers 404 by design, so the row
could only ever say "withheld", and every run of the test cost a miss in
the log for a sentence about Servette rather than about the connection.
The operator reads the version from `status` and from the Server tab.
**Worth recording, because it changes what the 404 buys:** the connection
test itself answers 200 to anyone, so Servette's presence is already
public. Withholding the version hides the version number, not the server.
*(2026-08-24)*

## A card folds, and destructive buttons look destructive

**Ruled (Human):** the trash button carries a border and the destructive
red at all times, not only under the pointer — the same shape every other
button has, in the colour the stop button already wears. Beside it, a
fold control (chevrons toward each other to close, away to open) hides
the card's body for a box serving more sites than fit on a screen.
**What folding keeps:** the head. A folded card still shows its name, its
controls, and — only while folded — the pill standing in for the Status
line, because the reason to fold is length, not secrecy, and a card that
hid whether it needed attention would make folding cost something.
**Fold state survives a re-render.** Every op re-renders the site list, so
a fold held on the card element would spring open on each save; it is
held by site instead, keyed on the domain where there is one, since
dragging renumbers indexes. *(2026-08-24)*

## A refusal describes the form as it stood

**Ruled (Human):** a validation refusal clears when the thing it described
changes — moving the access switch, or typing into the field it asked
for. It used to sit in red through every subsequent flip, describing a
form that no longer existed.
**Not a fault, and not counted as one:** a refused save changes nothing,
so the site gains no defect, and the head pill is right to stay where it
is. What was wrong was the message outliving its cause — and, separately,
where it appeared, which "A count, and one mark per problem where its
fix is" above closes. *(2026-08-24)*

## The card says what the site is, then what you do to it

**Ruled (Human):** what the site is — Status, Serving, Domain,
Certificate, Access — sits at the top of a site card. Publishing,
versions, redirects and the connection test follow underneath.
**Why:** the identity of the site answers the question a card is opened
to answer; the actions are what you do once you know it. The publish
strip led the card because publishing was the first thing the card could
do, which is history rather than a reason.
**And the remove panel is a popover under the button that opens it**,
rather than a block at the far end of a long card — a question asked
three hundred pixels from the thing you clicked is a question you have to
go and find. The rule against borrowed voices was always about the
browser's own dialogs (`alert`, `confirm`, `prompt`), never about panels
the page draws itself; the suite now pins that by reading the page's
JavaScript with comments stripped, since a prose mention of `confirm()`
is not a call to it. *(2026-08-24)*

## A redirect is any path you want to keep working

**Ruled (Human):** the wording assumes nothing about why. A redirect is
any path on this site sending visitors somewhere else — one that moved, a
short link worth remembering, a name you want to keep working. The page
labels them **Path** and **Sends visitors to**; the terminal spells the
pair `redirect=/path,/where-it-goes`.
**Why:** "old path" presumed the path used to exist and had been
abandoned, which is one reason among several and quietly told an operator
their other use was not what the feature was for. *(2026-08-24)*

## A fault has two severities, and an unsaved change is neither

**Ruled (Human):** red where the site cannot be used as it is configured;
amber where it serves and something still wants doing. Red: nothing to
serve, every visitor locked out by a username with no password, the
service stopped, and an untrusted certificate on a site that advertises a
domain — a full-page browser interstitial for everyone who visits by
name. Amber: a self-signed certificate on a site with no domain (that is
simply where every site starts), a half-built publish channel, low swap,
low disk, a missing watchdog. Every health row carries the severity, so
the card's pill, its Status line, and each row agree without deciding
separately.
**And a change typed but not saved is not a fault at all.** Flipping the
access switch used to paint the row in the same amber as a real defect,
which said "something is wrong here" about an intention the operator had
just formed. It reads as muted, italic, and says it is not saved yet.
**Why not all-red:** one colour cannot say both "visitors cannot use this
site" and "this works, and something wants doing" — and a first site,
freshly added and self-signed with no domain yet, would open in red on
its normal starting state. Crying wolf there costs the colour its meaning
where it matters.
**Also:** the Status line names what it counts ("2 to review — needs
certificate, needs password") rather than leaving a reader to work out
which rows the number meant. *(2026-08-24)*

## The 404 page leads with the connection, then the miss

**Ruled (Human):** the connection card sits above the 404 card, and the
404 card's thick left rule is gone.
**Why:** whether the server answered and whether the wire is encrypted
are true of the whole site and settle a visitor's first question; what is
missing is the narrower fact and follows it. The left rule marked the 404
card as the page's subject, which it no longer is. *(2026-08-24)*

## Missing paths is not a card Servette keeps

**Ruled (Human):** built to be looked at, looked at, and removed. The
journal still tallies what was served (`top_paths`); it no longer tallies
what was not.
**Why:** on a real box the list was dominated by scanners guessing
WordPress paths, one entry was Servette's own version endpoint answering
404 by design, and the one genuinely useful line — the site root missing
during an outage — is already visible as the outage itself. A card whose
top entries need explaining away is not reporting, it is generating work.
**Reopen if:** an operator asks which of their own links are broken,
which is the question this was reaching for and did not answer.
*(2026-08-24)*

## Publishing keeps a ring of versions, not a single-shot backup

**Ruled (Human):** publishing keeps the content it replaced, five deep
including the live one, and any of them goes live again from either
surface. The single `.bak` it replaces held exactly one, and a second
publish dropped it — so publishing twice on a bad day lost the good
version for good.
**Why not git**, which is what versioning is usually for: a `git checkout`
mutates a working tree file by file, and the property Servette is
proudest of is that a swap is one `os.replace` on a symlink with no
window a visitor can land in. Keeping that would leave git providing only
*storage* — a dependency to replace a directory rename, on content
(images, fonts, video) that git stores as full blobs with no delta
benefit and no bound on growth. It also does not preserve ownership, so
`_chown_operator` still runs; and a `.git` under a served folder is a
whole source history one hidden-path rule away from the internet.
**Rejected:** dulwich or any embedded git (above); a retention count as a
setting for now — five is a constant, and a setting is a decision of its
own if disk pressure makes it one. **Reopen if:** operators ask for
diffs between deploys, which is the one thing git would genuinely add —
though a diff of two file listings (name, size, hash) gets most of it
without the dependency. Git as an *input* (deploy on push) is a different
feature and remains open. *(2026-08-24)*

## Redirects are a setting, not a file in the site

**Ruled (Human):** an old path goes somewhere new, held per site in
config, validated at load, and served as a dict lookup before the
filesystem is touched. Editable from both surfaces; the terminal spells a
pair `set 0 redirect=/old,/new` and removes with nothing after the comma.
**Why:** the `_redirects`-file convention Netlify and Cloudflare use puts
the table in the site folder, where it is *content* — and content is read
at request time, which the request-time invariant forbids. This will come
up on every migration from those platforms, so the reason is recorded
rather than re-argued.
**Rejected:** the `_redirects` file (above); wildcards and splats for now
(exact paths first, which is where these systems stay simple).
**Settled, not open — the Agent raised this as a question it should not
have:** the status is **301**, permanent, which is what the feature is
for and what carries a link's standing to the new path. The hazard of a
301 is that browsers cache it hard, and a wrong one outlives fixing it —
but the response is sent `Cache-Control: no-cache`, which overrides that
default, so a browser re-asks and a corrected rule takes effect. 302 buys
nothing that the header has not already bought, and costs the thing the
feature exists for.
**Rejected:** 302 as a safer default (it is not safer; it is weaker).
*(2026-08-24)*

## A preview is content over the tunnel, not a deployment

**Ruled (Human):** Preview stages the chosen folder where only the admin
page can see it and shows it in a frame — did the CSS land, is the image
there, did the folder nest a level too deep. It is not HTTPS, not the
real domain, not the site's headers, and the page says so beside it.
**Why this shape:** real per-branch preview URLs need a wildcard
certificate and a DNS-01 challenge — a large new surface on a security
tool for a smaller benefit. Staging server-side rather than rendering the
browser's own copy is what makes relative links resolve, which is most of
what a preview is for.
**Three boundaries, all load-bearing:** the preview carries its own token,
never the run's passcode, because a previewed page can read its own URL
and a script in the operator's draft must not learn the credential that
publishes; that token sits in the URL *path*, because a draft's relative
links drop a query string (found in a browser — the page loaded and every
stylesheet was refused); and the frame withholds `allow-same-origin`, so
the draft has an opaque origin and cannot reach the page that staged it.
A preview belongs to one `admin` run and is cleared when it exits.
*(2026-08-24)*

## The footer says where more is written down

**Ruled (Human):** the admin page's footer ends with "More information is
available at **servette.org**", linked. Chosen over the alternative put
alongside it — linking the `Servette_` wordmark — so the wordmark stays
inert.
**Why (Agent, not part of the ruling):** the link opens in its own tab,
because the operator is mid-task on this page and a stray click on the
page's own name would abandon it.
Every footer link on every page points at **servette.org**, not at the
GitHub repository — the 404 body and the connection test included. The
404's footer reads exactly as the connection test's does: "Served by
Servette — The Simple, Secure, Static-Site Server." The sentence about
the page shipping inside Servette is gone from it; that is a fact about
the build, not something a visitor who hit a missing page needs.
*(2026-08-23)*

## The page is three tabs: a site is one card, the server is its own page

**Ruled (Human):** **Sites** holds one card per site carrying everything
about that site — publish, status, what it serves at, its domain, its
certificate, its access switch — so every question about a site is
answered in one place. **Server** holds what the box is doing and how it
is set. **Statistics** holds the measurements, last, because they are
consulted rather than worked in. The site dropdown is deleted outright:
a card per site needs no selector to say which site it means. The tab
is **Site** with one and **Sites** with more.
**Why:** the selector scoped half a tab and confused the other half —
three rounds of fussing over that control were really telling us the
structure was wrong. **Supersedes** "The page is two tabs" below.
**Rejected:** folding Statistics into Server (tried, and the Human
preferred measurement kept apart); "Site(s)" as a label (a parenthetical
plural where a count is already known). *(2026-08-23)*

## Naming a site and certifying it are two acts

**Ruled (Human):** `name` writes the domain into the config — instant,
and it cannot fail on someone else's DNS. `certificate` runs the
issuance, when the operator asks for it. Between them a site may sit
named but self-signed; that state is honest and loud on its card (amber,
with **Get certificate** beside it) rather than hidden inside one button.
**Why:** fused, a DNS mistake made *naming* appear to fail when the name
was perfectly fine to store. Split, the name saves and the certificate
becomes retryable — better failure semantics, and it is what the Human
saw before the Agent did. **Amends** "The domain is granted from the
Publish card" below.
**Two bugs the split exposed, both fixed in the same pass:** the
certificate op cannot judge itself by comparing the domain afterwards
(the name is already set by then, so failure would read as success) — it
reports `_obtain_trusted_cert`'s own verdict, distinguishing a refusal
from a transient network failure; and a renamed site keeps its old
certificate until a new one is asked for, so the health row compares the
certificate's subject against the site's name rather than reporting a
comfortable "89 days" about a certificate for somewhere else.
*(2026-08-23)*

## The page runs the service's lifecycle, never its installation

**Ruled (Human):** the Server status row carries **Restart** and one
button that is **Stop** while running and **Start** while stopped. Stop
asks first, in the page's own voice. `enable` and `disable` stay
terminal-only.
**Why the earlier line moved:** stopping was withheld on the premise
that a misclick could darken a box with no way back. The premise is
false — the page is served by the `admin` command's own process, not the
server's, so Start survives a stopped server and recovery is one click.
What the principle still forbids is *installation*: removing the unit
would take the page's own way back with it.
**Rejected:** three buttons where two carry the states (restart is
meaningless on a stopped server). *(2026-08-23)*

## Every button reads the same way, and the page never borrows the browser's voice

**Ruled (Human):** one look for every action button — Servette green
when it can be pressed, brighter on hover, dim (still green) and
unclickable when it cannot. Buttons stay put rather than appearing and
disappearing, so nothing a reader learned moves. Confirmation is drawn
by the page: the browser's own modal dialogs appear nowhere.
**And attention is a sentence, not a color:** a fault names itself
("Needs certificate", "Needs password"), amber carries the alarm without
an exclamation mark, and the one signal with nowhere else to live — the
server's own trouble — is a notice that says what is wrong and links
where to fix it. **Facts are not victories:** health rows read as
label-and-value, and only a row needing attention wears a mark.
*(2026-08-23)*

## The swapfile size is a setting on the page, as it always was in the terminal

**Ruled (Human):** setup has always asked "Swapfile size in MB [Enter =
1100, any size, n = skip]", so it is a number the operator picks, and the
page asks the same question — a field among the host settings, applied
by the same Save, resizing only when its number changed.
`_apply_swapfile` is the shared mechanical core (disk-space check,
swapoff, mkswap, the fstab line, and the failure path that rebuilds the
previous size rather than leaving a memory-tight host worse than it
started), so the two surfaces cannot drift.
**Rejected:** the Agent's "an operation, not a setting" resistance,
which did not survive contact with the code; a separate Resize button
(one Save covers every setting). *(2026-08-23)*

## The page reports an available upgrade; installing stays in the terminal

**Ruled (Human):** Server status names a newer release when PyPI has one,
and points at `pipx upgrade servette` — it never installs. The check is
asked for rather than volunteered: it happens because an operator opened
the page, is cached for six hours, times out in four seconds, and fails
silently, so a box with no route out costs nothing but that row.
**Why the line holds:** a self-updater would fetch, write into its own
venv, and restart itself mid-flight — the machinery ruled out by "`pip
install` is the only installation path" below. *(2026-08-23)*

## It is a connection test

**Ruled (Human):** the word is *test* — "test connection" is the idiom
people expect on a button, and consistency across the documents was an
argument against churn, not a reason the other word was better. Renamed
in both pages, the admin button, and every document. The source file is
`src/connection.html` — singular, because there is only one test, and
a connection-test spelling implied siblings that do not exist. The build
marker and the module's constants (`_CONNECTION_PAGE`,
`_CONNECTION_PATH`) follow the file. The reserved path stays
`/.well-known/servette-check`: it is a URL, and URLs that may be
bookmarked or linked from an already-published site are not renamed over
a word choice. The constant carries that note, so a reader meets the
explanation where they meet the mismatch.
The report leads with findings in the reader's language, each carrying
its evidence beneath in a footnote's voice; a public site withholding its
version reads as a pass, not a skip, because that is the design working.
**Rejected:** a bare test.html (reads as a developer's scratch page, and
collides in conversation with the suite's `tests/test.py`).
*(2026-08-23)*

## The front door is a login: link and passcode, printed apart

**Ruled (Human):** the terminal prints the stable link and this run's
passcode as two labeled lines; the bare bookmarkable URL answers a
login page in the admin tool's own dress — dark, the logo, the
tagline — whose one Passcode field submits the same `t` every request
carries. A bookmark is the expected door: it holds the link, never the
secret. With the flow itself teaching that the page rides the SSH
tunnel, the taglines drop the mechanism and state only what each page
is: **Login** on the door, **Admin** inside.
**Rejected:** the code-bearing `?t=` URL as the *printed* door (two
artifacts behaving differently — a magic link and a bare bookmark —
where one flow teaches itself); the unstyled pairing form (browser-
default white was the one off-brand surface in the family); "Admin —
your server, through your SSH tunnel" as the tagline (trying to be
punchy and failing — the Human's words). *(2026-08-23)*

## Sites are public or private, not password-less or protected

**Ruled (Human):** access is a property of the site, phrased that way
on every surface: Settings carries a literal switch — Private site,
on or off, the login fields existing only while it is on — the Access
health row answers "public — anyone can
view it" as a green fact, `sites` prints public/private, and the
production-issues list stops counting a public site against readiness.
The login fields exist only for a site that is private or becoming
private. What every surface flags instead is the genuine defect: a
username with nothing stored to check against, which locks every
visitor out — caught by the page and the terminal with one judgment.
**Why:** most sites are public on purpose; phrasing the absence of a
password as a warning taught operators their healthy site was broken.
*(2026-08-23)*

## Remove deletes the server's copies; deactivate is the pause

**Ruled (Human):** a site card's ✕ opens an in-card panel — never the
browser's own popup — offering the honest three-way: **Delete** (red)
removes the site's server copies with its config, the published tree,
slots, and backup, because those are derived from the operator's
originals in local storage and keeping them silently was disk nobody
could reclaim within Servette's two surfaces; **Deactivate** (amber)
keeps everything and stops serving — a real per-site setting
(`active`), honored by routing on every path, spelled `set n active=no`
in the terminal; **Cancel** (neutral). One explanatory bullet per
action. Delete spares certificate files (tiny; re-adding the same
domain skips re-issuance) and folders another site still points at.
This supersedes the files-on-disk-untouched clause of the site-cards
ruling below.
**Rejected:** "remove, keep the files" as a third option — silent
compounding, and a re-add collision waiting to happen; a green Cancel
(green invites clicking — neutral is the honest no-op). *(2026-08-23)*

## The domain is granted from the Publish card

**Ruled (Human):** naming a site is a Publish-card act. A domainless
card carries a Domain field and one button that runs the same
certificate issuance the terminal runs (`_obtain_trusted_cert`) — DNS
pointed at the box first, the button waiting out the issuance, failure
reporting the DNS question and leaving the self-signed fallback in
place. Encryption stays a Settings fact: the certificate health row
lives there, and Settings' domain row is read-only, pointing at the
card. This supersedes the "domain stays terminal-only" clauses of the
Config-tab and site-cards rulings below; what stays off the page now is
only what Servette itself cannot do — registering a domain and pointing
its DNS.
**Why:** the cards made and published sites but could not name them —
the one remaining door that opened from the terminal side only.
**Amended same day:** the field lives on every card, prefilled — a
domain is changeable anytime, not only at birth; re-submitting the
current name deliberately re-runs issuance (the repair path), and only
names other sites hold are refused.
**Rejected:** the domain field on Settings (naming belongs where sites
are born and published). *(2026-08-23)*

## The page is two tabs: Publish lands, Settings scopes

**Ruled (Human):** the admin page is Publish and Settings. Publish is
the landing tab — the site cards, the thing the operator came to do.
Settings is a site dropdown under the tabs scoping a **This site** card
(domain read-only with where it is granted, folder, that site's health
rows, its connection-check button — now checking the *selected* site,
not always site 0 — and the password form) above an unscoped **This
server** card (mode, version, the host health rows, the host settings).
Both render from one paired `/status` + `/config` fetch.
**Why:** the Status tab's rows grew linearly with sites while Config
already scoped per site — the same facts rendered twice, one of them
unboundedly.
**Accepted trade:** the at-a-glance health check moves one click from
page-open; softened by an amber count pill on the Settings tab saying
how many rows need review.
**Rejected:** scoping host facts under the site dropdown (a site
selector cannot scope the box); a third Status tab kept for the glance
alone (two renderings of the same rows, drifting). *(2026-08-22)*

## The folder is not a setting: serve_dir has left the vocabulary

**Ruled (Human):** where a site's content lives is Servette's business,
not a question an operator answers. Content arrives only by publishing —
the admin page's cards today, a terminal publish-from-folder to follow —
and the folder it lands in is Servette-assigned. `dir` leaves the
operator vocabulary (the Config tab already dropped it; `set dir=` and
the config sub-shell's `dir` follow); setup stops asking. The build
lands as its own commits at the end of this release's fixes, alongside
the pull-channel removal it overlaps.
**Why (user pov):** one less question with no wrong answer — every wrong
answer to the folder question is a guard elsewhere (containment,
secrets exposure, missing directory). **(developer pov):** those guards
outlive the setting only where paths still enter from config files
written by hand.
**Rejected:** keeping `dir` as an advanced terminal knob (the knob is
the footgun, not the surface it sits on).
**Built:** `_invent_site_dir` is the one folder-naming core, used by the
page's add-card and the terminal's `add-site` alike; `set dir=`, the
config sub-shell's `dir`, and setup's folder question are gone. The
containment guard the setting carried has no caller left, which is the
open question the ruling's developer-pov note anticipated. *(2026-08-22)*

## The Publish tab is the site list: cards add, move, and remove sites

**Ruled (Human):** one card per configured site — the drop strip with
the folder picker as a link inside it, and the card's own Publish
button — and the cards are the list itself: add, delete, and reorder in
place, in the notebook's cell grammar (drag the header — a ghost
follows, neighbours swap live — or the arrow buttons; ✕ confirms with
the terminal's exact promise). Order is config, not cosmetics: the
first domainless site answers unmatched Hosts, so a move saves and
reloads like any setting. Every op runs the same cores as the terminal
(`add-site` / `remove-site` / the new `move-site`), the page re-renders
from fresh `/config` truth after each, and `/upload` takes the card's
site index. A page-added site is born domainless — domain stays
terminal-bound to certificate issuance — and says so on its card.
**Rejected:** a single-site page with Config's dropdown as the only
multi-site surface (settings editable for sites the page couldn't
publish — the asymmetry the ruling started from). *(2026-08-22)*

## The Config tab is a password switch; the advanced knobs stay in the terminal

**Ruled (Human):** password protection is one visible switch — a toggle
that dims the username/password fields when off, states what saving
will do, and on disable deletes the login. The one-switch rule
("clearing the username clears the password with it") moves into the
shared validator, so `set username=`, the page, and the interactive
prompt behave identically — previously the first two left a stale hash.
The page learns the state from a `has_password` boolean; the hash never
crosses the wire, and a password riding with an emptied username is
refused whole rather than half-applied. Off the page and terminal-kept:
the serve folder, HTTPS port, and trusted proxy (behind-a-balancer
territory), the pull channel's URL/key pair (dying with the channel),
and every lifecycle verb. Every surviving field carries a one-line
always-visible hint.
**Rejected:** hover-only help icons (invisible until known, dead on
touch); lifecycle toggles on the page (root-prompting verbs that
narrate belong in the terminal, and a stop button one misclick from
darkness is a footgun — reopen if an operator SSHes in only to flip
the service). *(2026-08-22)*

## The connection test is its own reserved page; the 404 is a real 404

**Ruled (Human):** two public pages, each with one job. The default 404
body is a traditional error page — the path, the server-is-up sentence, a
home link, and a link to the check — and an operator's `404.html` takes
that role by simply existing. The connection test is its own embedded
page (`src/connection.html`) at `/.well-known/servette-check`: code-first, so
no site content ever shadows it; behind the site's own auth; answering
200, because the page really is there; its report rendering every row
upfront in a dimmed pending state and resolving each in place. The admin
page's Status tab pairs the two vantages by name: **Health checks** (what
the machine knows about itself) and the **connection test** (what a
browser sees from the internet's side of the wire).
**Why:** with the checks living inside the 404 body, the outside vantage
vanished the moment an operator shipped a custom 404.html — and the page
read as a contradiction, titled 404 while explaining there was no 404
page. This supersedes "The page has one role" below on that ruling's own
reopen trigger: the check returns as one named thing, not as a second
role — under `/.well-known/`, the namespace the hidden-path rule already
sets apart and the version endpoint already lives in, so the site's own
namespace stays unreserved.
**Rejected:** one dual-role page keyed off its own pathname (two headlines
in one file, forever); build-time page-include machinery to share the
check code between pages (new machinery for the same outcome);
"inside/outside" as the vantage names (reads as metaphor — the Human's
call). *(2026-08-22)*

## The Config tab sets the password; argv still never does

**Ruled (Human):** the admin page's Config tab carries a masked password
field. It travels only in the paired loopback POST — through the
operator's own SSH tunnel — and is hashed server-side by the same scrypt
path as the terminal prompt, under the prompt's own rules: username
first; blank means unchanged, never cleared; clearing the username is
what turns auth off. `set` keeps excluding password, because its
rationale is argv-specific — a secret on the command line leaks into
shell history and the process table — and never applied to the page.
Domain stays terminal-only on both surfaces: it is bound up with
certificate issuance.
**Rejected:** pointing the page's no-password attention row at a terminal
command — a browser page telling its reader to go run a shell is the
comprehension cliff again; the row links the Config tab instead.
*(2026-08-22)*

## The structural pass adopted the marks, not the moves

**Ruled (Human):** of the external feedback's six principles (#108), what
changes is what re-earned changing: SYSTEM reads runtime-first with the
install-time boundary marked ruthlessly (probes answer `status`; the writers
run once, as root, at setup/enable/disable; nothing below the line runs on a
request); DESIGN's residual how-it-got-here narrative is compressed to
present-tense constraints; the auth-timing property gets its pinning test.
What deliberately does not change, examined rather than skipped: SERVER
already reads request-path-pure — nine sections, no operator machinery,
nothing to move; and every item on the supporting-complexity roster
(privilege model, runtime copy, unit freshness, ownership plans, netwatch,
swap sizing) carries a ruling, a measurement, or a production drill — all
re-earn their load. SHELL's reshaping is deferred to the pull-channel
removal, which deletes a slice of it; restructuring twice is the waste.
*(#108, 2026-08-22)*

## The publish swap is a symlink flip; the window is gone

**Ruled (Human):** a site's content lives in one of two sibling slots
(`<serve_dir>.a`/`.b`) behind a `serve_dir` symlink. Publishing stages into
`<serve_dir>.new`, owns the tree to the operator before it goes live, moves
it into the idle slot, and swaps with one atomic `os.replace` of the link;
`serve_dir.bak` stays the single-shot marker (now a symlink to the previous
tree — the pre-flip era's real directory still restores), and restore-site
is the same flip in reverse, instant. A legacy real directory converts on
its first swap, paying the retired design's rename gap once per site ever.
**Why:** the two-rename swap had a moment in which the live directory did
not exist — a 404 under traffic, and a crash inside it left NO live content
behind a log line that said only "rejected." Measured rather than argued:
under the same four-reader hammer across 3,000 swaps, the old design missed
51,906 reads; the flip missed zero (the hammer exaggerates real request
rates — what it proves is a window existing versus being structurally
impossible).
**Rejected:** keeping the window as documented-and-proportionate (the
Human's question — "it can't be fixed?" — was the right one);
generation-numbered content directories (garbage collection and unbounded
states, where two slots need neither). *(#108, 2026-08-22)*

## Balancer compatibility is passive; active accommodations are out of scope

**Ruled (Human):** an external load balancer can front Servette on the
fittings that already exist — `trusted_proxy` with rightmost
X-Forwarded-For, the per-IP connection cap standing down behind a declared
proxy — plus the balancer's own configuration: health probes carrying the
site's Host header, and re-encryption to the HTTPS backend. Servette adds
no feature whose only justification is balancer convenience: no dedicated
health endpoint, no plain-HTTP backend mode, no PROXY protocol, no
multi-backend ACME — capability-shaped complexity, and multi-backend
scale-out sits outside "one site you own" by the scope principles besides.
**Reopen:** a real operator running Servette behind a balancer hits a wall
the fittings cannot configure around. *(#108, 2026-08-22)*

## One admin page with tabs is the browser surface

**Ruled (Human):** amending the paired-surfaces ruling below: the browser
half is one embedded page — `src/admin.html`, opened by `servette admin` —
with a tab per feature, not a page per feature. A feature earns a tab where
the browser genuinely beats the terminal: dashboards (Status) and file
picking (Publish) now, forms (Config) when built. Setup gets no tab — it
runs before the tunnel exists, so a browser setup page cannot reach its own
audience — and the lifecycle verbs (start/stop/enable/disable) stay
terminal-only: one-word commands with no multi-step pain, and a browser
button that stops the server serving the button is a footgun. Tabs are
fragment-addressable, so a paired terminal command can deep-link its own
tab. The loopback mechanism and every edge of the carve-out are unchanged.
Net shape: two embedded pages, one per audience — 404 for visitors on the
public surface, admin for the operator on the loopback surface.
**Rejected:** a page per feature (each page re-ships the scaffold, and the
operator collects a bookmark per feature — the duplication was already
visible with one page built). *(#108, 2026-08-22)*

## The 404 page is the outside view; the admin page is the inside view

**Ruled (Human):** the public error page keeps its connection report.
Everything it shows is computed from the response any client already holds
— headers, certificate, redirect, whether the root is published — so it
discloses nothing a one-request scan does not; the version readout stays
behind auth. Its copy leads green (a pitch, which on a secure-by-default
server is simply the checks passing), and failure rows are never hidden:
suppressing "nothing is published at the site root" would make the page lie
by omission to the operator it exists to help. Deeper self-testing —
service state, renewal watchdog, swap, disk — is the admin page's Status
tab, behind the tunnel, where the clearance is the SSH key.
**Rejected:** moving the self-test off the public page (deletes the outside
vantage — proof from the internet's side of the wire — and the no-login
diagnosis story, while denying an attacker nothing); showing only what
works. *(#108, 2026-08-22)*

## Multi-step features pair a shell flow with a loopback browser page

**Ruled (Human):** every multi-step feature eventually exists twice — a
guided SHELL flow and a browser page in the 404/pub visual family. The page
server binds 127.0.0.1 only, lives only while the operator's command runs,
and is reached through the operator's SSH tunnel: a one-time `LocalForward`
line beside the existing `ssh` shortcut, which setup prints at the moment
the operator is already paying attention. The command prints a clickable
URL carrying a per-run token; the bare URL is bookmarkable and asks for the
short code the terminal printed. Content entering through a page passes
through the identical staging, extraction-guard, atomic-swap, and backup
machinery the shell uses; the public surface is untouched — 405 to POST,
nothing network-reachable changes the server. This is the shell wearing a
friendlier skin (the transport is SSH), not a third way in.
**Why:** Servette's user has already proven exactly one skill — SSH into
their box. The page starts where they already stand and asks for nothing
new: no account, no credential, no hosted shelf. Same trailhead as the
terminal, easier grade.
**Order:** publish first, as the proof of concept (the pub page is most of
the visual work already); setup and config pages once it is proven.
**Rejected:** a public admin subdomain (an internet-facing upload door
guarded by a password — the most-scanned door on the web, and advertised in
certificate-transparency logs the moment its certificate exists);
auto-opening the browser from box output (terminals treat printed text as
inert by design — any server could otherwise pop pages on the operator's
screen); a client command installed on the operator's machine (client
software to build, distribute, and maintain — reopen if the one click per
publish session grates in practice, or a real browser-less-over-SSH need
appears). *(#108, 2026-08-22)*

## Tunnel uploads are authenticated by SSH; the pull channel is removed

**Ruled (Human):** content arriving through the loopback page carries no
signature — every hop is the operator's machine or their SSH connection,
and only the key holder can reach the door, so a signature would re-prove
an identity the transport already proved. Signatures remain the pull
channel's trust mechanism (they are what make an untrusted public shelf
safe) for as long as that channel exists — and its removal is the plan:
once the tunnel channel has served a real publish, the pull channel (the
fetch, signature verification, `config publish`, and the signing half of
the pub tool) is expected to go, with the Human confirming at that moment.
The staging/swap/backup core is shared with the page path and stays
regardless.
**Why:** no mainstream static server owns a content channel at all — how
files reach the folder is left to the operator. Pull was Servette's answer
before the page existed, and it forked off the DIY path by demanding
concepts from another world: signing keys, signatures, a hosted shelf.
**Rejected:** keeping pull forever as the advanced path (delegation and
cron-driven deploys are capability-shaped justifications, not
principle-shaped); removing it now, before its successor has served a
single real publish. **Reopen:** a real operator need to publish with no
SSH access at all.
**Built:** confirmed and removed on 2026-08-24 — the fetch, the
signature check, `config publish`, the two per-site settings, and the
`publish` sub-shell that had gathered the channel's verbs. What the two
channels shared (`_land_bundle`, the extraction guards, the version
ring, the publish lock) is untouched. The signing half of the pub tool
lives in the website repository and goes with its next pass.
*(#108, 2026-08-22)*

## The readability claim is "understood by one person," not "read in an afternoon"

**Ruled (Human):** the line count stays as a data point — an order of
magnitude under general-purpose servers, and the counts gate keeps whatever
number is stated true — but it is no longer pitched as evidence of *easy*
reading. The durable claim: the literate structure plus the size mean the
code can be **fully understood by one person** — a weekend's honest work,
not "an afternoon." The identity principle is renamed accordingly; README's
who-is-it-for framing and the website copy carry the same reframe, the
website fixed before its first publish so the site launches saying the true
thing.
**Rejected:** keeping "afternoon" (readers take it as a promise of an easy
read, which the code cannot keep and does not need to make); dropping the
line count (it is the measurable half of the claim, and the gates keep it
honest).
*(#108, 2026-08-21)*

## Swap demand is measured as Committed_AS, and the file cache is charged once

**Ruled (Human):** the swap estimate's demand term is `Committed_AS` plus the
file-cache ceiling not already inside it plus the spike allowance. The cache is
charged only where no live process holds it, which orders the offer above the
later status check by construction.
**Why:** the previous demand term (resident usage, plus the cache ceiling
unconditionally) had two faults, both measured rather than argued. It double-
counted a warm cache — 200 MB of cached files raise `Committed_AS` by 201 MB
and resident usage by 202 MB, so adding the ceiling on top cost up to 256 MB
of phantom swap after doubling. And it was noisy: resident usage wandered
9 MB over thirty seconds where `Committed_AS` did not move, and 9 MB becomes a
100 MB step after the doubling and rounding — which is how a host holding
exactly the recommended size was told to resize, with no size that would
satisfy the check.
**Rejected:** comparing against the recommendation recorded when the swapfile
was created — the Human's objection stands, that a first measurement taken at
an unrepresentative moment would become permanent truth and the check would be
immune to the evidence that should correct it. Also rejected: a percentage
tolerance band on the comparison, which was the Agent's recommendation until
the ordering property made it unnecessary — it treated the symptom, and a
threshold chosen to hide noise hides signal at the same width. Also rejected:
PSI (`/proc/pressure/memory`) as the trigger, which is evidence rather than
estimate and would be better, but is absent on kernels that ship it disabled
by default (needing psi=1 on the kernel command line) and so cannot be
depended on across Servette's platforms; and zram, which cannot absorb a spike larger than the RAM it
consumes.
**Accepted residual:** `Committed_AS` counts address space that may never be
touched, so a generous reserver inflates the estimate — the conservative
direction. The ×2 margin and the 700 MB spike allowance remain one
observation of one host, kept because published guidance offers nothing
better (Red Hat now calls its 2×RAM table impractical; Ubuntu's range spans
√RAM to 2×RAM).
**Reopen when:** PSI is dependably available across Debian, Ubuntu and
Raspberry Pi OS — an estimate should yield to evidence of actual memory
stalls the moment that evidence can be relied on. *(2026-08-19)*

## servette.toml is the operator's to read: servette:their group, 0640

**Ruled (Human):** the config is owned by the service user with the operator's
own group and mode `0640`. The read-only commands (`status`, `sites`, `log`)
then never ask for a password, and `config.unreadable` — the fail-closed guard
that refuses to report defaults as settings — stops firing during correct
operation.
**Why:** at `0600` the guard tripped on every configured host, so the operator
paid a password to look at their own box and a real warning became routine
noise. A guard that fires in normal use is one people learn to ignore. The
widening is from one system user to exactly one more, the operator, and world
bits stay off: the file carries a scrypt hash and its salt, which are material
for an offline attack.
**Rejected:** leaving `0600` and accepting the prompt (honest, but it teaches
the operator to type a password for read-only work and blunts the guard);
world-readable `0644`, which would hand the hash to every local account; and
having the read-only commands parse the file as root and drop the result, which
buys the same readability with a privileged code path instead of a file mode.
**Reopen if:** the config ever holds a secret rather than a verifier — a
plaintext token, an API key, a private key — at which point the operator's
convenience no longer outweighs keeping it to one user. *(2026-08-18)*

## A stale unit is noticed and told, not auto-refreshed (#99)

**Ruled (Human):** after an upgrade, the unprivileged shell notices the stale
systemd unit at launch and says so; `enable` — which elevates itself — is the
documented second half of an upgrade. `pipx upgrade servette` + `enable` is the
complete pair, and README documents exactly that.
**Why:** the alternatives put a password prompt at shell launch that the
operator did not ask for — the one place self-elevation would stop feeling
like Servette asking and start feeling like Servette demanding.
**Rejected:** the refresh elevating itself when stale (zero extra commands and
the old auto-refresh claim stays true, at the cost of an unprompted password
request on every launch until it succeeds); refreshing automatically only when
the shell happens to be root (two behaviors to test for a habit the install no
longer teaches).
**Reopen if:** operators demonstrably miss the `enable` step and run stale
services long after upgrading — the failure this trades away is silent
staleness, and evidence of it changes the balance. *(#99, 2026-08-17)*

## The cryptography floor is 48.0.1

**Ruled (Human):** `dependencies = ["cryptography>=48.0.1"]`, no ceiling. The
floor tracks Servette's actual exposure, not the dependency's total advisory
count: 48.0.1 is the lowest release whose statically-linked OpenSSL carries no
published advisory — bundled OpenSSL is in the process no matter which APIs are
called, so it sets the hard floor. Every advisory fixed above it
(CVE-2026-69247, PKCS#7 decryption; CVE-2026-69248/-69249, the X.509 chain
verifier) sits in APIs Servette never calls: its use of the library is X.509
load/generate, Ed25519 verification, RSA signing for ACME, hashes and
serialization.
**Corrects the record:** the previous floor (50.0) was set by the Agent inside
a merged commit, never surfaced as a decision, and its comment claimed
CVE-2026-69247 "affects every cryptography below 50.0.0" — false on the
advisory data (the CVE does not affect 41.x at all). The Human caught it.
**Rejected:** >=50.0, the only release with zero published advisories — free in
practice (a pipx install resolves newest regardless), but it encodes "no known
advisories anywhere in the library" where this ruling encodes "no known
advisories in what Servette runs," and the Human chose the scoped claim.
**Reopen when:** Servette starts calling the X.509 verifier or PKCS#7 APIs —
the call-graph scoping this floor rests on is then stale and the floor must be
re-derived. *(2026-08-17)*

## servette.py is committed to be read; the sources stay canonical

**Ruled (Human):** the generated `servette.py` is committed at the repository
root — the browsable single file — while `src/` remains the only source of
truth: the package build regenerates the module from the sources at every
install (`src/_literate_backend.py`), so what ships never depends on the
committed copy, and `build.py --check` holds the committed copy byte-for-byte
equal to the sources' build in CI.
**Narrows "`pip install servette` is the only installation path"
([above](#pip-install-servette-is-the-only-installation-path)):** a committed
module is inevitably also a copyable one, and the Human closes that with eyes
open — it was demonstrated before ruling that the copied file runs on a stock
host against the system cryptography (41.0.7 on the test image, below even
this ruling's floor), with no version resolution, no isolation, no upgrade
path — and self-elevation cannot re-invoke it, since sudo's child imports
servette by module name from paths the copied file is not on. The documented install remains exactly one: pipx. The copy path is
deliberately undocumented — not removed, not explained: operators who know
what to do with a single Python file do not need instructions, and everyone
else is told the one path that carries the dependency floor with it.
**Rejected:** not committing the module (drift-proof and enforces one-path
structurally, but leaves no program to read in the repository); committing it
and shipping the committed copy directly (simplest machinery, but PyPI would
then trust a file that can drift rather than the sources).
*(2026-08-17; supersedes the not-committed half of the 2026-08-17 single-file
build decision)*

## The build emits one servette.py; the package build runs the literate transform

**Ruled (Human):** the program is a single module again — `py-modules =
["servette"]`, no package directory, no `__main__.py` — and the
Markdown-to-module transform runs inside the package build itself:
`pyproject.toml` names `src/_literate_backend.py` (PEP 517, `backend-path`),
which generates `servette.py` from the sources and delegates to setuptools, so
pip, pipx and `python -m build` all perform the literate build on entry. The
wheel carries exactly `servette.py` beside its metadata.
**Why:** file count was never the identity claim, but one *visible, readable
file* is — and folding the build into the package manager removes a separate
step that could be forgotten and a class of staleness between it and what
ships. The `-m` entry point is the one subtlety: a single module runs as
`__main__` under `python -m servette`, so nothing in the module may derive its
own name from `__name__`.
**Rejected:** keeping the package layout (nothing wrong with it; it just served
no reader); dropping the literate sources for the plain module (deletes the
authored form the project is written in).
**Amended same day:** the module was first ruled not-committed; committing it
back is the ruling above this one. *(2026-08-17)*

## Servette asks for root; the operator never types sudo

**Ruled:** privileged commands elevate themselves. `run_command` re-runs the
command as `sudo <sys.executable> -m servette <cmd>` and returns to the prompt;
read-only commands (`status`, `sites`, `log`) stay unprivileged and never
prompt, unless the config is unreadable, when reporting stand-in defaults as the
operator's settings would be a lie.
**Why:** `sudo servette` forced the console script onto sudo's `secure_path`,
which forced the install to put it there — a symlink and a system-wide location,
two of the three lines the install needed. An absolute `sys.executable` needs
neither: sudo resolves it without consulting `PATH`.
**Consequences accepted:** `SERVETTE_HOME` is passed through explicitly, since
sudo resets the environment and losing it would silently point the elevated run
at another data directory. `start` and `stop` elevate only on the systemd path —
a session server lives in the shell's own process, where an elevated child could
neither outlive its own exit nor reach the parent's. The one-shot form exits with
sudo's status so tooling sees a refused password as a failure.
**Rejected:** requiring `sudo` in front of every invocation (the status quo, and
the cause of the install's shape); a setuid helper (a second privileged surface
to audit, for a program whose whole claim is that you can read it).
*(2026-08-17)*

## The service's runtime lives where the service user can read it

**Ruled:** `enable` measures whether the `servette` user can reach the installed
program. Where it cannot, `enable` copies the program and its dependency closure
into `RUNTIME_DIR` under the data directory — root-owned, world-readable, pinned
`ReadOnlyPaths` by the unit — and names that copy in `ExecStart`. `disable`
removes it, and so does an install the service *can* reach.
**Why:** a per-user install, which is what `pip install --user` and pipx
produce, sits under a home directory Debian and Ubuntu create mode 0750. The
service user cannot traverse it, so the unit restart-loops on
`ModuleNotFoundError` after the next reboot — invisible at install time, and the
exact failure Servette exists to prevent (#98).
**What is copied is read from metadata, not from a list here:** a list said
"cryptography" and produced a runtime that could not import it, because
cryptography declares cffi, cffi declares pycparser, and cffi's compiled backend
is a bare `.so` that only its `top_level.txt` names. A checkout has no dist-info
to read, so there the walk seeds from what `pyproject.toml` declares, and the
suite fails if those two lists disagree.
**The inference is executed, not trusted:** before any unit reaches disk,
`_verify_runtime` imports the program and the certificate machinery from the
paths the unit names, as the service user. A failure refuses the write. Every
other part of this ruling is inference about another user's view of a
filesystem, which is the kind of thing that is wrong quietly.
**Rejected:** granting the service user traverse into the operator's home (one
`chmod o+x`, but it weakens a distro default for every local account, against a
stated principle of never setting world bits); documenting a root-owned install
location instead (no code at all, but it puts `sudo` back in the install line,
and `pipx --global` is missing from the pipx Ubuntu 24.04 ships).
**Cost stated plainly:** 315 lines, to keep the install one line. Dropping the
per-user install path would delete all of them.
**Reopen if:** the distributions Servette targets stop creating home directories
unreadable to other accounts, which would make the copy dead weight.
*(#98, 2026-08-17)*

## The error page is inlined, not shipped as a file

**Ruled:** the page is authored as `src/404.html` — real HTML, editable
and openable in a browser — and `build.py` inlines it into the module at build
time. The install is Python only: one `servette.py` module.
**Why:** as package data it was a file an operator could delete, and deleting
it took the default 404 body with it silently — the server would go back to
answering ten bytes of `Not found.` with nothing to say why. A page that is
part of the module cannot be removed without removing the program.
**Rejected:** a Python string literal as the authored form (23 KB of HTML with
every quote escaped, no highlighting, unopenable in a browser) — the
precedent, the deleted placeholder page, showed why that reads badly; and
leaving it as package data with documentation asking operators not to delete
it. **Accounting:** the 576 lines of markup are reported separately by
`build.py --counts`, not folded into the Python figures. The counts back a
claim about reading the *program*; markup the program ships is not markup an
auditor reads to understand it. Stating that split openly is the point —
quietly absorbing 576 lines into "readable in an afternoon" would inflate the
claim. *(2026-08-17)*

## `pip install servette` is the only installation path

**Ruled:** there is one way to install Servette, and every other way is
removed rather than merely discouraged. The documented install is
`pip install servette`; nothing in the repository or its documents describes,
supports, or enables another. **Removed:** the
`git+https://` install and update commands from README; the `pipx`
alternative; and the website, which by living here let a checkout serve
servette.org and so kept clone-and-run alive as the shortest path
([above](#the-website-lives-in-its-own-repository)). **Not enforced in the
server:** an attempt to gate `enable` on the package sitting in
`site-packages` was made and reverted. Running as a supervised service that
survives reboots is one of the five principles — a core function of the
program — and a core function does not answer to a packaging question. The
scope of this ruling is what the project *offers and documents*, not a
capability withheld from a running server. Distribution is closed by having
one documented channel, not by crippling systemd. **Why so absolute:** a
second install path is a second thing to document, test, and support, and the
cheap one gets suggested — repeatedly — precisely because it exists. A
capability that is only discouraged is a capability. **Consequence accepted:**
until the first PyPI release the documented command does not work, and no
fallback is offered in its place. That is the point: the gap is visible
pressure to publish rather than a path that quietly substitutes for it.
**Reopen:** an operator population that genuinely cannot reach PyPI — in which
case the answer is a decided, documented second channel, not the return of an
undocumented one. **Narrowed:** the committed `servette.py` is copyable and
deliberately undocumented — see
[servette.py is committed to be read](#servettepy-is-committed-to-be-read-the-sources-stay-canonical).
*(2026-08-17)*

## The website lives in its own repository

**Ruled:** Servette's website moves to
[andy-emerson/websites](https://github.com/andy-emerson/websites) as
`servette.org/`, one directory per hostname, and leaves this repository. The
program repository holds the program. **Why:** while the site sat here as
`site/`, a checkout could serve it under `SERVETTE_HOME=.`, so "clone the
program and serve its own folder" was the shortest path to deploying
servette.org — which put this git repository inside the site's deployment
story and made installing-from-git a standing suggestion. Servette installs
from PyPI. Separation removes the shortcut instead of relying on anyone
declining to take it. **Moved with it:** the front page, the source viewer,
the publish tool, and the viewer's end-to-end harness (kept outside
`servette.org/`, since anything under a hostname directory is served
content). **Stayed:** the diagnostic page, which ships inside the
package because every install serves it. **Costs accepted:** the *exact* per-section
counts the site publishes can no longer be gated from here — the claim and its
source are in different repositories, so `build.py --counts` prints them and
nothing checks the page carries them. `--check-counts` survives, aimed at the
figures this repository still states about itself. And the viewer harness now
needs `SERVETTE_SRC` pointing at a checkout of this repository, so neither
repository tests that page alone. *(2026-08-17)*

## The status code tells the truth; the body does the work

**Ruled (principle).** Servette answers with the status code the situation
actually calls for, and puts its own contribution in the body. `200` is
`200`, `404` is `404`; the difference is that Servette's `404` is useful.
The status is the machine-readable half of the response — caches, crawlers,
uptime monitors — and is never bent to make a signal look better than the
thing it reports. Withholding is not bending: the closed-system miss and
the unserved version endpoint keep a true `404` and say less in the body.
**Scope:** every response Servette sends. It settles, without further
argument, soft-404s that answer `200` with an apology, a `200` at an
unpublished root to keep an uptime check green, and a `404` worn by a
refusal that is really a `403`. Described in
[DESIGN.md](DESIGN.md#the-status-code-tells-the-truth); the diagnostic
error page below is the case that made it explicit. **Reopen:** a standard
or a client Servette must interoperate with requires a status Servette
considers untrue — in which case the conflict is recorded, not resolved by
quietly bending one. *(2026-08-16)*

## The default error page diagnoses; the placeholder is retired

**Ruled:** every server needs an error page, so Servette's earns the
response it spends. Where the operator has written no `404.html`, a miss
is answered by the embedded diagnostic page — the same file served at
`/selftest/`, in a second role at status 404 — reporting that the server
is up, which host answered, the path requested, what the response
carries, and whether anything is published at the site root at all. That
last row separates a visitor who mistyped from an operator whose deploy
never landed. The page drops its Servette feature paragraph in the 404
role: an operator's error page is not this project's billboard. It never
enumerates the filesystem or guesses near-miss names, for the reason the
closed-system 404 stays a bare line — an error page that did would be a
file-discovery oracle. Because this answer covers a site's own root while
nothing is published there, the seeded placeholder page and its whole
`servette:demo` ownership protocol are deleted, superseding
[#70](https://github.com/andy-emerson/Servette/issues/70).
The status stays 404 throughout, per [the status code tells the
truth](DESIGN.md#the-status-code-tells-the-truth): a 404 is what happened,
and the diagnosis is the body's job. **Rejected:** the bare `Not found.`
(a whole response spent saying only that the reader was wrong); serving the
self-test verbatim, branding and feature advertisement included, as the
operator's error page; answering an unpublished root with 200 to restore
what the placeholder used to return — a monitor reading green over a site
with nothing to serve is the signal meaning less, which the principle
forbids. *(2026-08-16)*

## The error page is server-delivered, client-executed

**Ruled:** the page ships embedded in the module and is served as the default
404 body wherever the operator has written no `404.html`. Execution stays in the
visitor's browser — only an outside client sees the browser-trusted cert chain,
the real network path, and the provider firewall.
**Rejected:** server-side execution (a server cannot see itself from outside;
`_production_issues()` is already the inside half); the prior bundle-injected
copy (superseded from #42 — it required a deliberately duplicated page and a
network fetch in the publish tool). **Superseded within this ruling:** a second
role at a reserved `/selftest/` path answering 200, retired below.
*(#79, 2026-08-16; narrowed 2026-08-17)*

## The page has one role: there is no reserved path — *superseded*

**Ruled:** the page is Servette's 404 body and nothing else. `/selftest/` is an
ordinary path that 404s like any other, and no directory in a site root shadows
a reserved name.
**Why:** what the 200 role bought was one URL that answered 200 on an install
with nothing published yet. Everything else it did, a missing path already did —
the same page, the same checks, the same trusted padlock, at 404. That did not
pay for a reserved path, a status-code exception in the handler, a role branch
in the page, an override directory, and two names for one thing. Renaming the
file from selftest.html to diagnostics.html had made the naming worse rather
than better: "diagnostic" and "self-test" are synonyms, so the rename bought no
clarity while leaving 143 references pointing at the other name. One role means
one name, and it is the one every web server already uses.
**What is lost, stated plainly:** an operator with nothing published has no URL
on their own site that answers 200, and no monitor-friendly endpoint. That
follows from the status-code principle above rather than working against it: a
site with nothing published has nothing to serve.
**Rejected:** keeping the 200 role and giving it a user-facing name (`/status/`,
pairing with the shell's `status`) — coherent, but it keeps a reserved path and
a second framing to buy a convenience a missing path already provides.
**Reopen if:** operators are found routinely wanting a 200 health endpoint on a
site with no content, in which case it returns as one named thing, not as a
second role for this page. *(2026-08-17)*
**Superseded** (2026-08-22) by exactly that reopen condition: the check
returned as one named thing — see [the connection test's own reserved
page](#the-connection-test-is-its-own-reserved-page-the-404-is-a-real-404).
The 404 body keeps exactly one role, as this ruling wanted.

## site/pub/ is the operator tools page — *moved*

**Ruled:** one bookmarkable home for operator services — the publish
tool, the self-test explanation and link, the documented CLI loop. Its
ceiling is a security boundary: it hosts, ships, links, and explains,
and never reaches into a live server (no network admin API) or probes
another origin. `servette sign` (client-side signing verb in the pip
package) is **open**, not ruled. The page itself now lives at
`servette.org/pub/` in the websites repository; the ceiling above is a
property of the page and travelled with it. *(#79, 2026-08-16; moved
2026-08-17)*

## DECISIONS.md is the canonical decision record

**Ruled:** this file. DESIGN.md stays present-tense — what is built and
why it is shaped this way — pointing here where a ruling settled
something. Open work and deliberation live in GitHub issues.
**Rejected:** recording rulings as permanent narrative inside DESIGN.md
(the bloat mechanism: DESIGN's size tracked history, not the product);
GitHub Discussions (not version-controlled, not in a clone, invisible
offline — the working agreement requires decisions in the repository).
*(#78, 2026-08-16)*

## One home per fact: the site READMEs are deleted

**Ruled:** the website's folder READMEs are gone. The layout principle
lives with the site itself, and the publish tool's load-bearing
constraints live in that page's own header comment, where an editor of
the page reads them. Both files, and the pages they described, are now in
the websites repository. **Rejected:**
parallel folder READMEs (the merge-scale review caught them drifting
against DESIGN — two homes, one fact). *(#78, 2026-08-16)*

## No docs/ folder

**Ruled:** documents stay at repository root. README, CONTRIBUTING,
SECURITY, AGENTS.md, and CLAUDE.md are pinned there by platform and
tooling conventions, leaving only DESIGN.md and this file movable — a
folder for two files buys indirection and link-rot for no legibility.
**Reopen:** the movable document set outgrows three. *(#78, 2026-08-16)*

## SECURITY.md and CONTRIBUTING.md stay, slimmed to their cores

**Ruled:** both remain for their GitHub wiring — the Security tab's
private-reporting flow and the first-PR contributor banner — each
carrying only what that wiring puts in front of the right reader: the
reporting path and scope list; the generated-module rule, the
verification bar, and the credit-and-own AI policy. **Rejected:**
deletion (the two load-bearing facts would lose their GitHub-wired
home); folding into README (wrong audience). *(#78, 2026-08-16)*

## Distribution is pip/PyPI — Servette is not its own package manager

**Ruled:** install, upgrade, and rollback are the package manager's job;
the self-management layer (bootstrap, self-update, restore, the pinned
release-signing key, `servette.py.bak`) is deleted. The publish channel
is untouched — it guards operator *content* with per-site keys.
**Rejected:** signed GitHub releases + in-process self-update (hand-rolls
what the ecosystem standardized; its fetch-verify-swap-exec path was the
most dangerous code in the product); additive PyPI alongside it (forked
trust story). **Trade accepted:** code delivery trusts PyPI + Trusted
Publishing instead of a pinned Ed25519 key. **Reopen:** a PyPI
supply-chain incident touching Servette or its dependency, or credible
demand from operators on index-less networks. *(#77, 2026-08-15)*

## The data directory is /var/lib/servette

**Ruled:** state (config, certs, ACME account, site folders) lives in
`BASE_DIR` — `/var/lib/servette` on Linux, `~/.servette` in macOS
session mode, `SERVETTE_HOME` to override — never beside the code. Site
content is owned by the operator with servette-group read. **Rejected:**
beside-the-code (meaningless under pip); under `$HOME` (the 0750
home-traversal trap, root cause of #74). *(#77, 2026-08-15)*

## The CLI is the API

**Ruled:** `servette <command>` one-shot and the interactive shell share
one dispatcher; `status`/`sites --json` are the read half and validated
`set` the write half; SSH is the authentication. Password and domain are
deliberately excluded from `set` (argv leaks; certificate coupling).
**Rejected:** a network admin API — reaffirming the standing refusal;
nothing network-reachable changes the server. *(#77, 2026-08-15)*

## Servette ships as a package; the single-file principle is retired — *superseded*

**Ruled:** the build emits the `servette/` package; the literate `.md`
sources remain the canonical authored form; the identity principle is
**readable in an afternoon** — what an auditor must understand, not file
count. How many modules the package contains is an implementation
detail. **Rejected:** dropping the literate layer (deletes the reading
experience #69 invests in); keeping single-file output as a constraint
(no reader left to serve). **Superseded** (2026-08-17): the build emits one
`servette.py` again and the package build runs the transform — see
[the ruling](#the-build-emits-one-servettepy-the-package-build-runs-the-literate-transform);
the literate sources remain canonical, exactly as this ruling kept them.
*(#77, 2026-08-15)*

## The name is Servette

**Ruled:** appropriate for public release. The `-ette` reads in the
object-diminutive register (kitchenette, diskette) — "the little
server"; no adverse meaning in English or French, no colliding software
product, the Geneva sports clubs are a different domain. PyPI
registration is deliberate and deferred to the first release.
*(#77, 2026-08-15)*

## macOS is session mode; Windows is a non-goal

**Ruled:** Linux with systemd is the production target. macOS runs
everything but service installation. **Rejected:** a launchd port — no
ambient-capability equivalent or systemd sandbox, so a macOS *service*
would run with a weaker posture than the Linux one; session mode keeps
the posture honest. **Reopen (Windows):** credible demand from operators
who cannot run Linux or macOS. *(#64)*

## The publish tool's custody constraints

**Ruled:** the page that handles the operator's signing key is
dependency-free (no third-party script), signing-only (every capability
reduces to "produce a signed artifact the operator chooses to pull"),
and stores nothing extractable — the key is per-session, held as a
non-extractable `CryptoKey`, with IndexedDB remembering opt-in only.
**Accepted residual:** a compromised page could misuse a remembered key
while open, never steal it. **Rejected:** the CDN allowance the other
site pages get; extractable key storage. *(#42)*

## The placeholder page is embedded — *superseded*

**Ruled:** setup seeded an empty site from a page embedded in the module —
no network, no release asset — and the `servette:demo` marker was the
ownership protocol: marked pages were Servette's to refresh, unmarked
pages never touched, deleting the marker adopted the page.
**Rejected:** fetching a demo page from GitHub at setup (network
dependency and a degradation path for the first moment of use) — still
rejected, and the reason still holds for anything embedded.
**Superseded** by [the diagnostic error
page](#the-default-error-page-diagnoses-the-placeholder-is-retired): the
placeholder and the marker protocol are deleted, and setup keeps its
never-finish-with-nothing-to-serve promise without writing a file. *(#70,
superseded 2026-08-16)*

## The transport is stdlib http.server, owned directly

**Ruled:** HTTP/1.1 from the standard library with Servette owning the
hardening an ASGI server would otherwise supply — TLS from
`ssl.SSLContext`, the handshake off the accept loop, per-connection
timeout, connection caps. **Rejected:** an ASGI server (the largest
dependency, serving capability a static site doesn't need). *(recorded
in DESIGN's design-decisions list; migrated here)*
