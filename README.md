# Cognito Audit

A Lambda for populating a custom field on a Cognito user with details about their login.

## Configuration

You can adjust how the lambda responds with the following configuration options.

| Name                         | Description            | Default           |
|------------------------------|------------------------|-------------------|
| COGNITO_LAST_LOGIN_ATTRIBUTE | The last login details | custom:last_login |