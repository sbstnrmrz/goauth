package goauth

import (
	"fmt"
	"time"
)

// defaultResetEmail builds the reset message, returning subject, plain text and
// HTML bodies. Override Config.ResetEmail to change the copy or its language.
func defaultResetEmail(name, link string, expiry time.Duration) (string, string, string) {
	minutes := int(expiry.Minutes())

	subject := "Reset your password"

	text := fmt.Sprintf(`Hi %s,

We received a request to reset your password. Open the link below to choose a new one:

%s

This link expires in %d minutes and can only be used once.

If you didn't request a password reset, you can ignore this email - your password will stay the same.`, name, link, minutes)

	html := fmt.Sprintf(`<p>Hi %s,</p>
<p>We received a request to reset your password. Click the link below to choose a new one:</p>
<p><a href="%s">Reset your password</a></p>
<p>This link expires in %d minutes and can only be used once.</p>
<p>If you didn't request a password reset, you can ignore this email &mdash; your password will stay the same.</p>`, name, link, minutes)

	return subject, text, html
}
