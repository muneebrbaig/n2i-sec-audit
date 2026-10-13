# Stack adapter: Node.js and Python

Load when `STACKS` includes `node` or `python`. This adapter is a starting set of patterns for common frameworks. If the project uses something else, fall back to `references/stacks/generic.md` and add what you learn to the report's method section.

## Node.js (Express, Fastify, NestJS, Next.js)

**A1** `\.query\(|\.raw\(|sequelize\.query|knex\.raw|\$queryRawUnsafe|\$executeRawUnsafe` with template literals or `+`.
**A2** `dangerouslySetInnerHTML|innerHTML|v-html|bypassSecurityTrust`.
**A3** `csurf|csrf|SameSite|sameSite` and how sessions are carried.
**A4** `multer|formidable|busboy|express-fileupload`: check limits, MIME-by-content, storage path.
**A5** `axios\.|fetch\(|got\(|request\(` with variable URLs.
**A6** `Object\.assign\(.*req\.body|\.\.\.req\.body|node-serialize|eval\(|new Function\(|vm\.runIn`.
**B2** `express-rate-limit|rate-limiter-flexible|@nestjs/throttler`; check the key function.
**B3** `bcrypt|argon2|scrypt|pbkdf2|crypto\.createHash\(['"](md5|sha1|sha256)`: a bare fast hash for passwords is a gap.
**B5** Middleware order; routes without an auth middleware; NestJS `@UseGuards`, global guards.
**C1** `jsonwebtoken|jose` : `jwt.verify` options (`algorithms`), secret source, `expiresIn`.
**C2** `NEXT_PUBLIC_|VITE_|REACT_APP_` variables holding secrets; `.env*` handling; `next.config.js` `env` block.
**C3** `localStorage|sessionStorage` with token values.
**D1** `cors\(|origin:\s*true|origin:\s*['"]\*['"]`.
**D3** `productionBrowserSourceMaps|devtool|sourcemap: true` in build configs; Swagger/GraphQL playground exposure.
**D4** `console\.log\(.*(password|token|secret)|logger\.\w+\(.*req\.(body|headers)`.
**D5** `npm audit --omit=dev` (in `scan.py`). Check a lockfile exists.
**D6** `helmet\(` and its options, or the framework's header config.

## Python (Django, Flask, FastAPI)

**A1** `\.raw\(|cursor\.execute\(.*(%|\+|format|f['"])|text\(f|execute\(f`.
**A2** `mark_safe|\|safe\b|autoescape off|Markup\(|render_template_string`.
**A3** Django `CsrfViewMiddleware`, `csrf_exempt`; Flask-WTF `CSRFProtect`.
**A4** `request\.files|UploadFile|FileField`: check validators, size limits, storage.
**A5** `requests\.(get|post)|httpx|urllib` with variable URLs.
**A6** `pickle\.loads|yaml\.load\((?!.*Loader=yaml\.SafeLoader)|marshal|exec\(|eval\(` and serializers with `fields = '__all__'`.
**B2** `django-ratelimit|slowapi|flask-limiter|DRF throttle`.
**B3** Django `PASSWORD_HASHERS`, `AUTH_PASSWORD_VALIDATORS`; `passlib`, `bcrypt`, `argon2`. Flag `hashlib.md5|sha1` for passwords.
**B5** DRF `permission_classes` and `DEFAULT_PERMISSION_CLASSES`; FastAPI `Depends` on auth; views with no auth.
**C1** `SECRET_KEY` source in Django settings; `jwt.decode(` options (`algorithms=`, `verify_signature`).
**C4** `createsuperuser` scripts and fixtures with fixed passwords.
**D1** `CORS_ALLOW_ALL_ORIGINS|CORS_ORIGIN_ALLOW_ALL|allow_origins=\[.\*.\]`.
**D3/D7** Django `DEBUG = True`, `ALLOWED_HOSTS = \['\*'\]`; Flask `debug=True`; FastAPI docs routes exposed.
**D4** `logging\.\w+\(.*(password|token|secret)`.
**D5** `pip-audit` (in `scan.py` when installed) or `safety`; lockfile (`poetry.lock`, `requirements.txt` with pins).
**D6** Django `SECURE_*` settings, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`.
