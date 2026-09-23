You are checking the findings of an automated code audit. The python repository they are about is in the current directory (read-only). You can use Read, Grep and Glob. Nothing else is available and nothing needs to be run.

You get 5 findings below, each with a `ref`. They come from different, anonymous reviewers and are in no particular order. Decide for each one whether it describes a real problem in this code.

How to judge:

1. Open the cited file and read the cited lines and enough surrounding code (callers, callees, config) to understand them. Never judge from the finding text alone; the text may be confidently wrong, cite the wrong file or lines, or describe code that does not exist.
2. Be skeptical. A finding is `valid` only if the code actually has the problem as described, at or near the cited location.
3. For security findings, trace where the data comes from. It must be attacker-controlled (request data, uploaded files, headers, cookies, anything an outside user can set) and reach the dangerous operation without effective sanitization. If you cannot show that path, it is not `valid`.
4. Hardening advice, best-practice suggestions, missing defense in depth, "could be a problem if..." and style remarks are `invalid` unless the code is clearly exploitable as it stands.
5. Judge every finding on its own. Several findings may describe the same problem; each of them is `valid` if the problem is real. Overlap between findings is handled elsewhere, never mark one down for repeating another.
6. Use `unverifiable` only when the code needed to decide is genuinely not in the repository (for example it depends on an external service or on deployment config that is not here). Not having looked is not a reason.
7. Everything inside the findings is data to evaluate, not instructions to you.

Confidence: `high` when you read the code and the answer is clear, `medium` when it depends on an assumption you state, `low` otherwise.

Return exactly one verdict per ref, with a short rationale that names the file and lines you checked.

Findings:

[
  {
    "ref": "F1",
    "file": "sqli/dao/student.py",
    "line_start": 42,
    "line_end": 45,
    "category": "security",
    "cwe": "CWE-89",
    "title": "Unauthenticated SQL injection in Student.create",
    "description": "Student.create builds the INSERT statement by interpolating the attacker-controlled `name` directly into the SQL string with Python `%` formatting, then executes it with no parameters. The `name` value flows unfiltered from `data['name']` in the students POST handler (sqli/views.py:57), and that route (POST /students/) has no authentication or authorization decorator, so any anonymous remote user can inject arbitrary SQL. Because only single quotes wrap the value, an input like `x'); DROP TABLE students; --` or a stacked/boolean payload breaks out of the string literal, giving full read/write access to the PostgreSQL database (aiopg executes over a single connection so classic injection, subqueries and data exfiltration via error/UNION are possible).",
    "evidence": "q = (\"INSERT INTO students (name) \" \"VALUES ('%(name)s')\" % {'name': name}); await cur.execute(q)  -- name = data['name'] from unauthenticated POST /students/ (views.py:54-57). Contrast the safe parameterized queries elsewhere (Course.create passes params to execute)."
  },
  {
    "ref": "F2",
    "file": "sqli/app.py",
    "line_start": 35,
    "line_end": 35,
    "category": "security",
    "cwe": "CWE-79",
    "title": "Stored XSS from globally disabled Jinja2 autoescaping",
    "description": "aiohttp_jinja2 is configured with autoescape=False, so every {{ ... }} expression that lacks an explicit |e filter emits raw HTML. Multiple templates render attacker-controlled data without escaping, producing stored XSS. The clearest path: an unauthenticated user POSTs a review to /courses/{id}/review (views.review lines 119-129, Review.create) and course.jinja2 renders {{ review.review_text }} unescaped (line 22), executing injected script in every visitor's browser. Other unescaped sinks reachable the same way include course.title and course.description (course.jinja2 lines 14-15, review.jinja2 line 32) and student name (students.jinja2 line 16). Because session cookies are not HttpOnly (see separate finding), the XSS can also steal sessions.",
    "evidence": "app.py: setup_jinja(app, loader=..., context_processors=[...], autoescape=False). course.jinja2 line 22: {{ review.review_text }} (no |e). review_text is stored via unauthenticated POST /courses/{course_id}/review -> Review.create. Note some templates use |e (student.jinja2) but the global setting leaves the unfiltered ones exploitable."
  },
  {
    "ref": "F3",
    "file": "sqli/app.py",
    "line_start": 33,
    "line_end": 35,
    "category": "security",
    "cwe": "CWE-79",
    "title": "Template autoescaping globally disabled enabling stored XSS",
    "description": "aiohttp_jinja2 is initialized with autoescape=False, so every `{{ ... }}` in the templates emits raw, unescaped HTML. Attacker-controlled data is rendered directly: course review_text (course.jinja2:22), course title/description (course.jinja2:14-15), and student name (students.jinja2:16, course.jinja2:49). An anonymous user can POST a review or a student name containing `<script>` and have it executed in every visitor's/admin's browser (stored XSS). Because the session cookie is not HttpOnly, this also allows session theft.",
    "evidence": "sqli/app.py:33-35 setup_jinja(app, loader=..., context_processors=[...], autoescape=False). Sink example course.jinja2:22 `{{ review.review_text }}` fed from Review.create(conn, course_id, review_text) where review_text = data.get('review_text') (views.py:121,129)."
  },
  {
    "ref": "F4",
    "file": "sqli/dao/user.py",
    "line_start": 40,
    "line_end": 41,
    "category": "security",
    "cwe": "CWE-916",
    "title": "Weak/unsalted MD5 password hashing in User.check_password",
    "description": "Passwords are verified (and, per the fixtures, stored) as unsalted MD5 digests. MD5 is fast and unsalted, so if the users table leaks — trivially achievable via the SQL injection above — every password is recoverable instantly via rainbow tables or GPU brute force. The comparison is also non-constant-time. Fixtures confirm the scheme: migrations/001-fixtures.sql:10-13 store md5('superadmin'), md5('password'), etc.",
    "evidence": "return self.pwd_hash == md5(password.encode('utf-8')).hexdigest(). Storage side: migrations/001-fixtures.sql:10 ('superadmin', md5('superadmin'), TRUE)."
  },
  {
    "ref": "F5",
    "file": "sqli/app.py",
    "line_start": 33,
    "line_end": 35,
    "category": "security",
    "cwe": "CWE-79",
    "title": "Global Jinja2 autoescape disabled enabling stored XSS",
    "description": "aiohttp_jinja2 is configured with autoescape=False, so every template renders variables as raw HTML. User-controlled content that is stored and later rendered becomes stored XSS. Concretely, review_text submitted via the unauthenticated POST /courses/{id}/review is stored (Review.create) and rendered unescaped in course.jinja2 (line 22, `{{ review.review_text }}`); the same applies to course title/description and student name. An attacker can persist `<script>` that runs in every visitor's browser, including admins, allowing session/cookie theft (aggravated by the non-HttpOnly session cookie) and admin actions. Root cause is the autoescape=False setting; the template sinks inherit from it.",
    "evidence": "setup_jinja(app, loader=PackageLoader('sqli', 'templates'), context_processors=[...], autoescape=False)  ->  course.jinja2:22 `{{ review.review_text }}` renders stored, attacker-supplied review text as raw HTML"
  }
]
