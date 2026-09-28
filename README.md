# Containerized CLI Login

A Go command-line login system with password authentication, optional TOTP two-factor authentication, account lockout, and persistent sessions. PostgreSQL runs in Docker and stores accounts, sessions, recovery codes, and authentication events.

## Quick start

Requirements: Docker with Compose v2 and `make` (or run the equivalent Docker commands below).

```sh
make setup       # create .env, generate the encryption key, build the image
make up          # start PostgreSQL
make cli         # open the interactive shell
```

Without `make`:

```sh
cp .env.example .env
docker compose run --build --rm --no-deps cli genkey
# Paste the generated value into APP_ENCRYPTION_KEY in .env.
docker compose up -d db
docker compose run --rm cli
```

The CLI applies database migrations at startup. `docker compose down` keeps database data; `docker compose down -v` deletes it. Keep `.env` and `APP_ENCRYPTION_KEY` private. Losing the key means enrolled TOTP secrets cannot be decrypted.

## Commands

Before login: `register`, `login`, `help`, `exit`.

After login: `whoami`, `enable-2fa`, `disable-2fa`, `history`, `logout`, `help`, `exit`.

The shell supports command history, tab completion, masked password entry, and account/session details after login. Use `help <command>` for command guidance.

## Distribution

This is a Go executable, so npm is not its natural package registry. Install from the Go module after the repository is public:

```sh
go install github.com/elyashium/Containerized-CLI-Login-System-with-2FA/cmd/cli-login@latest
```

Tagged releases (`v1.0.0`, for example) are configured to publish ready-to-run Linux, macOS, and Windows archives on GitHub Releases. Docker Compose remains the recommended way to run the full application with PostgreSQL.

To publish a release after pushing your changes, create and push a version tag:

```sh
git tag v1.0.0
git push origin v1.0.0
```

## Development

```sh
go mod tidy
go build ./cmd/cli-login
go test ./...
```

For configuration options, see [`.env.example`](.env.example).

## Repository

[GitHub: Containerized CLI Login System with 2FA](https://github.com/elyashium/Containerized-CLI-Login-System-with-2FA)
