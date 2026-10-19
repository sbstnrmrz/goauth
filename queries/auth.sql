-- name: CreateUser :one
INSERT INTO users (name, email, username, image, role)
VALUES (
    sqlc.arg(name),
    sqlc.narg(email),
    sqlc.narg(username),
    sqlc.narg(image),
    COALESCE(NULLIF(sqlc.arg(role)::text, ''), 'user')
)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users
WHERE id = $1;

-- name: CreateAccount :one
INSERT INTO accounts (user_id, provider_id, account_id, password)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetAccountByEmail :one
SELECT * FROM accounts
WHERE account_id = $1 AND provider_id = $2;

-- name: GetAccountByUsername :one
SELECT accounts.* FROM accounts
JOIN users ON users.id = accounts.user_id
WHERE users.username = $1 AND accounts.provider_id = $2;

-- name: GetAccountByUserID :one
SELECT * FROM accounts
WHERE user_id = $1 AND provider_id = $2;

-- name: UpdateAccountPassword :exec
UPDATE accounts
SET password = $1, updated_at = now()
WHERE user_id = $2 AND provider_id = $3;

-- name: SetUserDisabled :exec
UPDATE users
SET disabled_at = CASE WHEN sqlc.arg(disabled)::boolean THEN now() ELSE NULL END,
    updated_at = now()
WHERE id = sqlc.arg(id);
