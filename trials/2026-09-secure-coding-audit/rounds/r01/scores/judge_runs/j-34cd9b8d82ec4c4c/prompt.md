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
    "file": "sqli/middlewares.py",
    "line_start": 20,
    "line_end": 20,
    "category": "security",
    "cwe": "CWE-1004",
    "title": "Session cookie set with HttpOnly disabled",
    "description": "RedisStorage is instantiated with httponly=False, so the session cookie is readable by client-side JavaScript. Given the stored XSS (autoescape disabled), an attacker's injected script can read document.cookie and exfiltrate the session, leading to full account/session takeover. No Secure flag is set either.",
    "evidence": "storage = RedisStorage(app['redis'], httponly=False)"
  },
  {
    "ref": "F2",
    "file": "sqli/app.py",
    "line_start": 23,
    "line_end": 30,
    "category": "security",
    "cwe": "CWE-489",
    "title": "aiohttp application runs with debug=True",
    "description": "The Application is created with debug=True, which enables verbose diagnostics and can surface internal details/warnings. Shipping debug mode to a non-development environment increases information disclosure risk.",
    "evidence": "app = Application(debug=True, middlewares=[...])"
  },
  {
    "ref": "F3",
    "file": "sqli/app.py",
    "line_start": 23,
    "line_end": 30,
    "category": "security",
    "cwe": "CWE-489",
    "title": "Application runs with debug=True",
    "description": "The aiohttp Application is created with debug=True and run.py configures logging at DEBUG level. In a deployed setting this increases the chance of verbose diagnostics and sensitive detail leaking, and disables some production safeguards.",
    "evidence": "app = Application(debug=True, middlewares=[...]) ; run.py:11 logging.basicConfig(level=logging.DEBUG)"
  },
  {
    "ref": "F4",
    "file": "sqli/dao/user.py",
    "line_start": 40,
    "line_end": 41,
    "category": "security",
    "cwe": "CWE-916",
    "title": "Passwords hashed with unsalted MD5",
    "description": "Password verification compares the stored hash to md5(password). MD5 is fast and unsalted here, so any breach of the users table (readily achievable via the SQL injection above) exposes passwords to trivial rainbow-table/brute-force cracking. It also uses a non-constant-time == comparison.",
    "evidence": "return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()"
  },
  {
    "ref": "F5",
    "file": "sqli/dao/user.py",
    "line_start": 40,
    "line_end": 41,
    "category": "security",
    "cwe": "CWE-916",
    "title": "Weak, unsalted MD5 password hashing in User.check_password",
    "description": "Passwords are stored and verified as a single unsalted MD5 digest. MD5 is fast and broken for password storage: if the users table leaks (readily reachable via the SQL injection above), attackers can crack passwords near-instantly with rainbow tables / GPU brute force, and identical passwords produce identical hashes. The comparison is also non-constant-time.",
    "evidence": "user.py:40-41 def check_password(self, password): return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()"
  },
  {
    "ref": "F6",
    "file": "sqli/views.py",
    "line_start": 134,
    "line_end": 153,
    "category": "security",
    "cwe": "CWE-862",
    "title": "Missing authorization on mark-assignment endpoint (evaluate)",
    "description": "The evaluate handler assigns grades (Mark.create) but has no @authorize decorator and performs no session/role check, even though the UI only exposes this action to admins (course.jinja2 guards the form with {% if auth_user.is_admin %}). Any unauthenticated user can POST /students/{id}/evaluate/{course_id} to tamper with student marks. The same lack of authorization applies to the students, courses, and review create handlers; the authorize(ensure_admin=...) helper exists but is only used on logout.",
    "evidence": "@template('evaluate.jinja2') async def evaluate(request): ... await Mark.create(conn, student_id, course_id, data['points']) -- no get_auth_user/authorize call anywhere in the handler."
  },
  {
    "ref": "F7",
    "file": "sqli/views.py",
    "line_start": 134,
    "line_end": 153,
    "category": "security",
    "cwe": "CWE-862",
    "title": "Missing authorization on state-changing endpoints (evaluate, create student/course/review)",
    "description": "The evaluate handler assigns marks to students but performs no authentication or authorization check. The UI only shows the evaluate form to admins (course.jinja2:41 `{% if auth_user.is_admin %}`), but the backend route POST /students/{id}/evaluate/{course_id} is not protected, so any unauthenticated visitor can POST arbitrary grades. The authorize()/authorize(ensure_admin=True) decorator (utils/auth.py:12-23) exists but is applied only to logout. The same missing-check pattern affects the create paths in views.students (line 54-57), views.courses (line 86-90), and views.review (line 119-129), all of which mutate data with no auth check.",
    "evidence": "async def evaluate(request): ... await Mark.create(conn, student_id, course_id, data['points']) -- no @authorize decorator; contrast logout at views.py:156 which uses @authorize(). The template gates the form on auth_user.is_admin but the route does not."
  },
  {
    "ref": "F8",
    "file": "sqli/app.py",
    "line_start": 23,
    "line_end": 24,
    "category": "security",
    "cwe": "CWE-489",
    "title": "Application runs with debug mode enabled",
    "description": "The aiohttp Application is constructed with debug=True unconditionally (not gated on an environment/config flag). In a deployed environment this enables verbose diagnostics and can leak internal details in error output, aiding an attacker.",
    "evidence": "sqli/app.py:23-24 app = Application(debug=True, middlewares=[...])."
  },
  {
    "ref": "F9",
    "file": "sqli/middlewares.py",
    "line_start": 20,
    "line_end": 20,
    "category": "security",
    "cwe": "CWE-1004",
    "title": "Session cookie not marked HttpOnly",
    "description": "The Redis-backed session storage is created with httponly=False, so the session cookie is readable by client-side JavaScript. Given the stored XSS enabled by autoescape=False, an attacker's injected script can exfiltrate the session cookie via document.cookie and hijack the victim's authenticated session, including an admin's.",
    "evidence": "middlewares.py:20 `storage = RedisStorage(app['redis'], httponly=False)`."
  },
  {
    "ref": "F10",
    "file": "sqli/app.py",
    "line_start": 25,
    "line_end": 30,
    "category": "security",
    "cwe": "CWE-352",
    "title": "CSRF protection middleware disabled application-wide",
    "description": "The csrf_middleware that validates the per-session _csrf_token on POST requests (sqli/middlewares.py:25-38) is commented out of the middleware chain, so no CSRF validation occurs even though templates embed csrf tokens. Every state-changing POST (login, add student, add course, submit review, evaluate, logout) can be triggered cross-site. An attacker can host a page that auto-submits a form to, e.g., /courses/{id}/review or /students/{id}/evaluate/{course_id} against an authenticated victim. The SameSite cookie flag is also not set (see cookie finding), so browsers do not mitigate this by default.",
    "evidence": "middlewares=[session_middleware, # csrf_middleware, error_middleware] — csrf_middleware is present in the source but excluded from the active list."
  },
  {
    "ref": "F11",
    "file": "sqli/app.py",
    "line_start": 24,
    "line_end": 30,
    "category": "security",
    "cwe": "CWE-352",
    "title": "CSRF protection disabled (csrf_middleware commented out)",
    "description": "A working CSRF middleware exists (sqli/middlewares.py:25-38) and templates already embed a _csrf_token hidden field, but the middleware is commented out of the application's middleware list, so no CSRF validation happens on any POST. Combined with the session cookie being sent automatically, an attacker page can force a logged-in admin's browser to submit forms (create courses/reviews, evaluate students, log the user out). The token is generated by csrf_processor but never checked.",
    "evidence": "middlewares=[ session_middleware, # csrf_middleware, error_middleware ]. The disabled check lives in middlewares.py:26-38 (token compared against formdata['_csrf_token'])."
  },
  {
    "ref": "F12",
    "file": "sqli/middlewares.py",
    "line_start": 20,
    "line_end": 20,
    "category": "security",
    "cwe": "CWE-1004",
    "title": "Session cookie set without HttpOnly flag",
    "description": "RedisStorage is instantiated with httponly=False, so the session cookie is readable by JavaScript. Combined with the XSS exposure (autoescape disabled), an injected script can steal the session cookie and hijack authenticated/admin sessions.",
    "evidence": "storage = RedisStorage(app['redis'], httponly=False)"
  },
  {
    "ref": "F13",
    "file": "sqli/app.py",
    "line_start": 24,
    "line_end": 30,
    "category": "security",
    "cwe": "CWE-352",
    "title": "CSRF protection middleware commented out",
    "description": "A working csrf_middleware exists (middlewares.py:25-38) and templates render `_csrf_token` hidden fields, but the middleware is commented out of the application middleware list. As a result none of the state-changing POST endpoints (login, create student, create course, create review, evaluate, logout) validate the CSRF token, so an attacker can forge cross-site requests that perform these actions on behalf of a logged-in victim (including an admin evaluating students).",
    "evidence": "sqli/app.py:25-29 middlewares=[session_middleware, # csrf_middleware, error_middleware]. The disabled check lives in middlewares.py:25-38."
  },
  {
    "ref": "F14",
    "file": "sqli/dao/user.py",
    "line_start": 40,
    "line_end": 41,
    "category": "security",
    "cwe": "CWE-916",
    "title": "Passwords hashed with unsalted MD5",
    "description": "check_password compares the stored hash against an unsalted single-round MD5 of the supplied password. MD5 is fast and unsalted, so if the users table is exposed (readily achievable via the SQL injection above), password hashes fall instantly to rainbow tables / GPU cracking, and identical passwords across users share a hash.",
    "evidence": "return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()"
  },
  {
    "ref": "F15",
    "file": "sqli/app.py",
    "line_start": 24,
    "line_end": 30,
    "category": "security",
    "cwe": "CWE-352",
    "title": "CSRF protection middleware disabled application-wide",
    "description": "The Application is created with a middleware list that omits csrf_middleware (it is commented out), even though a working csrf_middleware exists in sqli/middlewares.py and templates emit a _csrf_token hidden field. As a result none of the state-changing POST endpoints (login, student creation, course creation, review creation, student evaluation, logout) validate a CSRF token. An attacker can host a page that auto-submits a form to these endpoints and perform actions in the context of an authenticated victim (e.g. force an admin to evaluate students, or create/modify data). Additionally the session cookie's non-HttpOnly, default SameSite behaviour does not mitigate this.",
    "evidence": "middlewares=[session_middleware, # csrf_middleware, error_middleware]. csrf_middleware is defined at sqli/middlewares.py:25-38 but never added to the app."
  }
]
