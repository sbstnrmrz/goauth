-- name: CreateSession :one
INSERT INTO sessions (token, user_id, expires_at, ip_address, user_agent)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetSessionByToken :one
SELECT sqlc.embed(sessions), users.role FROM sessions
JOIN users ON users.id = sessions.user_id
WHERE sessions.token = $1;

-- name: DeleteSession :exec
DELETE FROM sessions
WHERE token = $1;

-- name: DeleteSessionsByUserID :exec
DELETE FROM sessions
WHERE user_id = $1;
