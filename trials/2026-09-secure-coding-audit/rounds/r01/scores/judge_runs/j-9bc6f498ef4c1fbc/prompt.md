You are checking the findings of an automated code audit. The python repository they are about is in the current directory (read-only). You can use Read, Grep and Glob. Nothing else is available and nothing needs to be run.

You get 15 findings below, each with a `ref`. They come from different, anonymous reviewers and are in no particular order. Decide for each one whether it describes a real problem in this code.

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
    "title": "Unauthenticated SQL injection in Student.create via string-formatted INSERT",
    "description": "Student.create builds the INSERT statement by Python %-formatting the attacker-controlled student name directly into the SQL string instead of passing it as a bound parameter. The value comes from request.post()['name'] in views.students (sqli/views.py:57), a POST /students/ handler that performs NO authentication check, and with the CSRF middleware disabled the request needs no token. An attacker can therefore submit a name like `x'); DROP TABLE marks; --` or `x'),(...)--` to break out of the string literal and execute arbitrary SQL against the PostgreSQL database (data exfiltration, modification, or destruction). This is the primary, most severe vulnerability in the app.",
    "evidence": "q = (\"INSERT INTO students (name) VALUES ('%(name)s')\" % {'name': name})  then  await cur.execute(q)  -- name flows unescaped from views.py:57 `await Student.create(conn, data['name'])` where data = await request.post(). Contrast with the safe parameterized queries in course.py/review.py/mark.py which pass a params dict as the second execute() argument."
  },
  {
    "ref": "F2",
    "file": "sqli/middlewares.py",
    "line_start": 20,
    "line_end": 20,
    "category": "security",
    "cwe": "CWE-1004",
    "title": "Session cookie set with HttpOnly disabled",
    "description": "RedisStorage is instantiated with httponly=False, so the session cookie is readable from JavaScript. Combined with the disabled autoescape/stored XSS, injected scripts can exfiltrate the session cookie and hijack authenticated (including admin) sessions.",
    "evidence": "storage = RedisStorage(app['redis'], httponly=False)"
  },
  {
    "ref": "F3",
    "file": "sqli/dao/user.py",
    "line_start": 40,
    "line_end": 41,
    "category": "security",
    "cwe": "CWE-916",
    "title": "Passwords hashed with unsalted MD5 in User.check_password",
    "description": "User passwords are verified (and, per the schema/fixtures, stored) as a plain unsalted MD5 hex digest. MD5 is fast and unsalted, so if the users table leaks (e.g. via the SQL injection above), passwords are trivially recovered with rainbow tables or GPU cracking. The equality comparison is also non-constant-time. This affects all accounts including admins.",
    "evidence": "from hashlib import md5\n...\ndef check_password(self, password: str):\n    return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()"
  },
  {
    "ref": "F4",
    "file": "sqli/app.py",
    "line_start": 24,
    "line_end": 24,
    "category": "security",
    "cwe": "CWE-489",
    "title": "Application runs with debug mode enabled",
    "description": "The aiohttp Application is constructed with debug=True unconditionally. In production this enables verbose diagnostics/tracebacks and developer-oriented behavior that can leak internal details (stack traces, source paths) to clients and increases attack surface.",
    "evidence": "app.py:23-24: app = Application(debug=True, middlewares=[...])."
  },
  {
    "ref": "F5",
    "file": "sqli/dao/student.py",
    "line_start": 42,
    "line_end": 45,
    "category": "security",
    "cwe": "CWE-89",
    "title": "SQL injection in Student.create via unparameterized name interpolation",
    "description": "Student.create builds its INSERT statement with Python string formatting ('...VALUES (\\'%(name)s\\')' % {'name': name}) instead of passing parameters to cur.execute. The name value is fully attacker-controlled: the POST /students/ handler (sqli/views.py:57) calls Student.create(conn, data['name']) directly from request.post() with no validation and no authentication decorator on the route (sqli/routes.py:14). An attacker can submit a name such as ' ); DROP TABLE marks; -- or use stacked/subquery payloads to read or modify any data, since the value is concatenated straight into the query text before execution. This is the one place the injection actually happens; every other DAO method (Course.create, Review.create, Mark.create, get/get_many) correctly uses bound parameters.",
    "evidence": "q = (\"INSERT INTO students (name) \" \"VALUES ('%(name)s')\" % {'name': name})  # name from data['name'] in views.students (POST /students/), then cur.execute(q) with no params"
  },
  {
    "ref": "F6",
    "file": "sqli/middlewares.py",
    "line_start": 20,
    "line_end": 20,
    "category": "security",
    "cwe": "CWE-1004",
    "title": "Session cookie set without HttpOnly flag",
    "description": "RedisStorage is instantiated with httponly=False, so the session cookie is accessible to client-side JavaScript. Given the stored XSS above, an attacker can read document.cookie and exfiltrate the session identifier to fully hijack accounts, including the superadmin. The cookie is also not marked Secure, allowing interception over plaintext HTTP.",
    "evidence": "storage = RedisStorage(app['redis'], httponly=False) in session_middleware."
  },
  {
    "ref": "F7",
    "file": "sqli/app.py",
    "line_start": 33,
    "line_end": 35,
    "category": "security",
    "cwe": "CWE-79",
    "title": "Stored XSS via globally disabled Jinja2 autoescaping",
    "description": "aiohttp_jinja2 is configured with autoescape=False, so all template variables are rendered as raw HTML unless a template explicitly adds |e. User-controlled data is echoed unescaped in multiple templates, e.g. course.jinja2 renders {{ review.review_text }}, {{ course.title }}, {{ course.description }} and {{ student.name }} without escaping. review_text is submitted by any user via POST /courses/{id}/review (views.review) and stored, giving persistent XSS that fires for every viewer of the course page. Combined with the non-HttpOnly session cookie, this enables session hijacking.",
    "evidence": "setup_jinja(app, loader=..., autoescape=False) in app.py; sqli/templates/course.jinja2:22 renders {{ review.review_text }} unescaped; review_text originates from request.post() in views.review (views.py:121-129)."
  },
  {
    "ref": "F8",
    "file": "sqli/views.py",
    "line_start": 134,
    "line_end": 153,
    "category": "security",
    "cwe": "CWE-862",
    "title": "Missing authorization on state-changing and admin endpoints",
    "description": "The evaluate handler assigns marks to students but performs no authentication or authorization check, even though the UI exposes this action only to admins (templates/course.jinja2:41 gates the form behind auth_user.is_admin). Any unauthenticated client can POST to /students/{id}/evaluate/{course_id} and create marks. The same missing-auth pattern affects other mutating handlers: students (POST /students/, views.py:51-60) creates students, and courses (POST /courses/, views.py:83-93) creates courses, all without @authorize. Only logout uses the authorize() decorator. The authorize decorator itself (sqli/utils/auth.py:12-23) is correct but simply not applied.",
    "evidence": "async def evaluate(request): ... await Mark.create(conn, student_id, course_id, data['points']) -- no get_auth_user/authorize call. Compare logout at views.py:156 which is decorated with @authorize(). Admin-only intent shown by templates/course.jinja2:41 {% if auth_user.is_admin %}."
  },
  {
    "ref": "F9",
    "file": "sqli/middlewares.py",
    "line_start": 20,
    "line_end": 20,
    "category": "security",
    "cwe": "CWE-1004",
    "title": "Session cookie set with HttpOnly disabled",
    "description": "The Redis session storage is instantiated with httponly=False, so the session cookie is exposed to client-side JavaScript. Combined with the stored XSS enabled by autoescape=False, an injected script can read document.cookie and exfiltrate the session identifier, allowing full session hijacking of any authenticated (including admin) user who views attacker-controlled content.",
    "evidence": "storage = RedisStorage(app['redis'], httponly=False)  # sqli/middlewares.py:20"
  },
  {
    "ref": "F10",
    "file": "sqli/dao/user.py",
    "line_start": 40,
    "line_end": 41,
    "category": "security",
    "cwe": "CWE-916",
    "title": "Passwords hashed with unsalted MD5",
    "description": "User.check_password compares the stored hash against md5(password) with no salt and no work factor. MD5 is fast and broken for password storage: if the users table is disclosed (readily achievable via the SQL injection above), attackers can crack passwords near-instantly with rainbow tables / GPU brute force. Equal-length string comparison with == is also non-constant-time.",
    "evidence": "user.py:41: return self.pwd_hash == md5(password.encode('utf-8')).hexdigest(). Import at user.py:1 from hashlib import md5."
  },
  {
    "ref": "F11",
    "file": "sqli/middlewares.py",
    "line_start": 20,
    "line_end": 20,
    "category": "security",
    "cwe": "CWE-1004",
    "title": "Session cookie set with httponly disabled",
    "description": "The Redis-backed session storage is created with httponly=False, so the session cookie is exposed to client-side JavaScript. Given the stored XSS made possible by the disabled autoescaping, an injected script can read document.cookie and exfiltrate the session identifier, enabling full session hijacking of any user (including admins).",
    "evidence": "storage = RedisStorage(app['redis'], httponly=False) -- the default of True is explicitly overridden to False."
  },
  {
    "ref": "F12",
    "file": "sqli/app.py",
    "line_start": 23,
    "line_end": 24,
    "category": "security",
    "cwe": "CWE-489",
    "title": "Debug mode enabled on the aiohttp Application",
    "description": "The Application is constructed with debug=True, and run.py sets logging to DEBUG. Debug mode enables more verbose diagnostics and framework warnings that can leak internal details, and DEBUG logging risks recording sensitive request data. This should never be enabled in a production deployment.",
    "evidence": "app = Application(\n    debug=True,\n    middlewares=[...])\n\nrun.py:11 -> logging.basicConfig(level=logging.DEBUG)"
  },
  {
    "ref": "F13",
    "file": "sqli/app.py",
    "line_start": 23,
    "line_end": 30,
    "category": "security",
    "cwe": "CWE-489",
    "title": "Application runs with debug=True exposing error details",
    "description": "The aiohttp Application is constructed with debug=True. In production this enables verbose diagnostics and detailed error output which can leak stack traces, internal paths and configuration to clients, aiding further exploitation. The config (config/dev.yaml) also ships default postgres/postgres credentials.",
    "evidence": "app = Application(debug=True, middlewares=[...])"
  },
  {
    "ref": "F14",
    "file": "sqli/views.py",
    "line_start": 134,
    "line_end": 153,
    "category": "security",
    "cwe": "CWE-862",
    "title": "Missing authorization on state-changing endpoints (evaluate, student/course/review creation)",
    "description": "The evaluate handler assigns marks to a student for a course but has no @authorize decorator and performs no server-side role check; only the template hides the form behind `{% if auth_user.is_admin %}` (sqli/templates/course.jinja2:41). Any anonymous client can POST to /students/{id}/evaluate/{course_id} with a `points` value and record grades, defeating the intended admin-only control. The same missing-authorization pattern affects the other mutating handlers: students create (sqli/views.py:54-57), courses create (sqli/views.py:86-89), and review create (sqli/views.py:119-129) are all reachable unauthenticated. The authorize() decorator exists (sqli/utils/auth.py:12-23) but is applied only to logout.",
    "evidence": "@template('evaluate.jinja2')\nasync def evaluate(request): ... await Mark.create(conn, student_id, course_id, data['points'])  # sqli/views.py:134-153, no @authorize\nCompare: only logout uses @authorize()  # sqli/views.py:156"
  },
  {
    "ref": "F15",
    "file": "sqli/middlewares.py",
    "line_start": 20,
    "line_end": 20,
    "category": "security",
    "cwe": "CWE-1004",
    "title": "Session cookie readable by JavaScript (HttpOnly disabled)",
    "description": "The Redis session storage is created with httponly=False, so the session cookie is exposed to client-side JavaScript. Given the stored-XSS exposure from disabled auto-escaping, an attacker's injected script can read document.cookie and exfiltrate the session, taking over accounts including superadmin. No Secure or SameSite flag is configured either, so the cookie is also sent over plaintext and cross-site.",
    "evidence": "storage = RedisStorage(app['redis'], httponly=False)"
  }
]
