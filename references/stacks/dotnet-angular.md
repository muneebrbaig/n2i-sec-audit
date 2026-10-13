# Stack adapter: .NET (ASP.NET Core) and Angular

Load when `STACKS` includes `dotnet` or `angular`. Each section names the checklist ID and where to look. Use `Grep` with the patterns shown. Quote the pattern, and run searches from the repo root and name the backend and frontend directories in each command.

## Backend (ASP.NET Core, EF Core)

**A1 SQL injection**
- `FromSqlRaw|ExecuteSqlRaw|SqlQueryRaw|FromSql\(|ExecuteSql\(` . Interpolated `FromSqlInterpolated`/`ExecuteSqlInterpolated` are parameterized; `Raw` with `$"..."` or `+` is not.
- `new (Npgsql|Sql)Command|CommandText` . Check for string building. Offline tooling (migration utilities) is lower risk than request-path code; say which is which.

**A4 File upload.** `IFormFile|multipart|Request.Form.Files`.

**A5 SSRF.** `HttpClient|AddHttpClient|GetFromJsonAsync|PostAsync` . For each, ask where the URL comes from.

**A6 Mass assignment / deserialization.** `BinaryFormatter|TypeNameHandling|\[FromBody\]` with entity types instead of DTOs.

**B1 BOLA / multi-tenancy.**
- Find the tenant-scoping helper and list its call sites. Then list service methods that read or write tenant tables without it.
- `HasQueryFilter` shows which entities have a central filter.
- Look for forwarding of a resolved organization id into nested calls that re-check roles.
- Check id types: sequential `int` keys are guessable.

**B2 Rate limiting.** `AddRateLimiter|RequireRateLimiting|EnableRateLimiting|UseRateLimiter`. Check every defined policy is applied to something, and what `partitionKey` reads (a request header is client-controlled).

**B3 Passwords.** `AddIdentity|IdentityOptions|PasswordHasher|Password\.Required|Lockout`.

**B4 MFA.** `TwoFactor|Authenticator|TOTP|RecoveryCodes`. A `TwoFactorEnabled` property with no enrollment or sign-in step is a gap.

**B5 Authorization.** `\[Authorize|AllowAnonymous|FallbackPolicy|RequireAuthenticatedUser|AddAuthorization`. List controllers or actions with no attribute and no base-class attribute. Without a `FallbackPolicy`, a forgotten attribute means open. Custom authorize attributes: read them to see what they trust (token claim versus datastore).

**B6 RLS.** Search migration scripts for `ENABLE ROW LEVEL SECURITY|CREATE POLICY`. Check the connection's role.

**B7 Sessions/tokens.** Token lifetime options, refresh-token storage (hashed?), `access_token` read from the query string (SignalR hubs often do this).

**C1 Signing keys.** `IssuerSigningKey|SymmetricSecurityKey|Jwt:Key|ValidAlgorithms|ValidateLifetime`. Count the places that validate tokens; more than one means drift risk.

**C2 Secrets server-side.** Read `appsettings*.json` and environment examples for key-shaped values. Check which config values reach the SPA (runtime config files, `environment*.ts`).

**C4 Defaults.** Seed scripts and setup docs for default accounts. Check the existence and git-ignore status of local credential files (`git check-ignore -v <path>`), without reading them.

**D1 CORS.** `AddCors|UseCors|WithOrigins|AllowAnyOrigin|AllowAnyHeader|AllowAnyMethod|AllowCredentials`.

**D2 Webhooks.** Anonymous endpoints: `\[AllowAnonymous\]` plus API-key or signature attributes. Check constant-time comparison (`FixedTimeEquals`).

**D3 Debug surfaces.** `UseSwagger|UseDeveloperExceptionPage`: confirm they are environment-gated.

**D4 Logs.** `LogInformation|LogWarning|LogError|LogDebug` lines mentioning `password|token|otp|secret|apikey|authorization`. Check no-op sender modes that log message bodies. Check Serilog destructuring or redaction.

**D6 Headers/transport.** `UseHsts|UseHttpsRedirection|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Referrer-Policy|UseForwardedHeaders`. Note a commented-out HTTPS redirection.

**D7 Error leakage.** `UseExceptionHandler|ProblemDetails|ex.Message` returned to clients.

**D8 Audit.** Search for audit-log tables and writes on login, role change, and cross-tenant access.

**D5 Dependencies.** `dotnet list <solution> package --vulnerable --include-transitive` (also in `scan.py`).

## Frontend (Angular)

**A2 XSS.** `innerHTML|\[innerHTML\]|bypassSecurityTrust|DomSanitizer|outerHTML|document\.write|eval\(`. For each `[innerHTML]`, trace the value's source and any custom pipe that builds markup.

**C2 Secrets in the bundle.** Read `environment*.ts`, runtime-config files, `set-env.js`-style scripts. Grep the built output directory for key-shaped strings (use `scripts/secret_scan.py` on it).

**C3 Token storage.** `localStorage|sessionStorage|IndexedDB` with `setItem`. Look for whole user objects stored. Check interceptors and realtime clients that read tokens back.

**D3 Source maps.** `sourceMap` in `angular.json` per configuration; count `.map` files in the build output.

**D5 Dependencies.** `npm audit --omit=dev` from the frontend directory. Mobile wrappers (Capacitor, Cordova) are dependencies too.

**D6 CSP compatibility.** Inline scripts/styles and `eval` usage determine how strict a CSP can be.
