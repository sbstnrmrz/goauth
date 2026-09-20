-- name: CreateVerification :one
INSERT INTO verifications (identifier, value, expires_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetVerificationByIdentifier :one
SELECT * FROM verifications
WHERE identifier = $1;

-- name: DeleteVerification :execrows
DELETE FROM verifications
WHERE identifier = $1;

-- name: DeleteUserResetTokens :exec
-- The 'password-reset:%' literal here must stay in sync with resetTokenPrefix
-- in token.go, which builds every identifier this matches. Changing one
-- without the other silently stops this delete from matching.
DELETE FROM verifications
WHERE value = $1 AND identifier LIKE 'password-reset:%';
