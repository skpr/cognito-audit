# Cognito Audit

A Lambda for populating a custom field on a Cognito user with details about their login.

## Configuration

You can adjust how the lambda responds with the following configuration options.

### Login Lambda

| Name                         | Description                    | Default                    |
|------------------------------|--------------------------------|----------------------------|
| COGNITO_LAST_LOGIN_ATTRIBUTE | The last login details         | custom:last_login          |

### Report Lambda

| Name                         | Description                    | Default                    |
|------------------------------|--------------------------------|----------------------------|
| COGNITO_LAST_LOGIN_ATTRIBUTE | The last login details         | custom:last_login          |
| EMAIL_FROM                   | Email from address             |                            |
| EMAIL_TO                     | Email to address               |                            |
| EMAIL_SUBJECT                | The email's subject            | User Audit Report - [date] |
| FILE_NAME                    | The filename of the attachment | UAR-[date].json            |
