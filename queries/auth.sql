-- name: CreateUser :one
INSERT INTO users (name, email, image)
VALUES ($1, $2, $3)
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

-- name: GetAccountByUserID :one
SELECT * FROM accounts
WHERE user_id = $1 AND provider_id = $2;

-- name: UpdateAccountPassword :exec
UPDATE accounts
SET password = $1, updated_at = now()
WHERE user_id = $2 AND provider_id = $3;
