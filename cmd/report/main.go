package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/caarlos0/env/v11"
	"github.com/skpr/yolog"
)

const (
	// YoLogStream is the log stream name for yolog logs.
	YoLogStream = "cognito-audit-report"
)

// Config is the environment based configuration for this lambda.
type Config struct {
	// UserPoolID is the ID of the Cognito user pool to report on.
	UserPoolID string `env:"COGNITO_USER_POOL_ID,required"`
}

// Event is the input event for this lambda. It is currently empty as this
// lambda is expected to be triggered on a schedule (e.g. via EventBridge)
// rather than in response to a specific payload.
type Event struct{}

func main() {
	lambda.Start(handler)
}

// handler is the lambda entrypoint. It loads configuration and AWS clients
// before delegating to run.
func handler(ctx context.Context, _ Event) error {
	logger := yolog.NewLogger(YoLogStream)
	defer logger.Log(os.Stdout)

	var lambdaConfig Config

	err := env.Parse(&lambdaConfig)
	if err != nil {
		return logger.WrapError(err)
	}

	logger.SetAttr("user_pool_id", lambdaConfig.UserPoolID)

	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return logger.WrapError(err)
	}

	client := cognitoidentityprovider.NewFromConfig(awsConfig)

	err = run(ctx, logger, client, lambdaConfig, os.Stdout)
	if err != nil {
		return logger.WrapError(err)
	}

	return nil
}

// run reads all users from the configured Cognito user pool, paginating
// through the full result set, and prints them out to the provided writer.
func run(ctx context.Context, logger *yolog.Logger, client *cognitoidentityprovider.Client, config Config, w *os.File) error {
	paginator := cognitoidentityprovider.NewListUsersPaginator(client, &cognitoidentityprovider.ListUsersInput{
		UserPoolId: &config.UserPoolID,
	})

	var total int

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}

		for _, user := range page.Users {
			err = printUser(w, user)
			if err != nil {
				return err
			}
			total++
		}
	}

	logger.SetAttr("total_users", total)

	return nil
}

// printUser writes a human-readable summary of a Cognito user to the
// provided writer.
func printUser(w *os.File, user types.UserType) error {
	username := ""
	if user.Username != nil {
		username = *user.Username
	}

	_, err := fmt.Fprintf(w, "username=%s status=%s enabled=%t", username, user.UserStatus, user.Enabled)
	if err != nil {
		return err
	}

	return nil
}
