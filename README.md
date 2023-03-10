# go-editor-builder

This repository implements a minimal build server for [go-editor](https://github.com/alex-nicoll/go-editor).

When a build dependency changes, the server is notified via a GitHub Webhook. The server then builds and pushes a new image to Docker Hub. If the build fails for some reason, the server sends an email notification to `alex.nicoll@outlook.com`.

### Setup

This section is intended for personal use, as the application currently works only for my specific use case (hardcoded file names, email addresses, etc).

Elastic Email is used as an outgoing mail server. This requires a small amount of setup:
1. Create an Elastic Email account. 
2. [Create SMTP credentials](https://app.elasticemail.com/api/settings/create-smtp), obtaining a secret key to pass to the application as an environment variable.
3. [Verify](https://app.elasticemail.com/api/settings/domains/email-verification/) the email address that will be used as the sender (`code.alexn@gmail.com`).

Once cloned, the application is invoked as follows:
```
WEBHOOK_SECRET=[GitHub Webhook secret] EMAIL_AUTH_SECRET=[Elastic Email secret] go run .
```
