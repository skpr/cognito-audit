package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/caarlos0/env/v11"
	"github.com/skpr/yolog"

	audittypes "github.com/skpr/cognito-audit/internal/types"
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

type Export struct {
	Timestamp time.Time    `json:"timestamp"`
	Total     int          `json:"total"`
	Users     []ExportUser `json:"users"`
}

type ExportUser struct {
	Username  string     `json:"username"`
	Email     string     `json:"email"`
	Status    string     `json:"status"`
	Enabled   bool       `json:"enabled"`
	LastLogin *time.Time `json:"last_login"`
}

func main() {
	// Nicest way to facilitate running report locally and via lambda.
	if os.Getenv("AWS_LAMBDA_RUNTIME_API") == "" {
		ctx := context.Background()
		event := Event{}
		err := handler(ctx, event)
		if err != nil {
			log.Fatal(err)
		}
	}

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

	err = run(ctx, logger, client, lambdaConfig)
	if err != nil {
		return logger.WrapError(err)
	}

	return nil
}

// run reads all users from the configured Cognito user pool, paginating
// through the full result set, and prints them out to the provided writer.
func run(ctx context.Context, logger *yolog.Logger, client *cognitoidentityprovider.Client, config Config) error {
	paginator := cognitoidentityprovider.NewListUsersPaginator(client, &cognitoidentityprovider.ListUsersInput{
		UserPoolId: &config.UserPoolID,
	})

	export := Export{
		Timestamp: time.Now().UTC(),
	}

	var total int

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return err
		}

		for _, user := range page.Users {
			lastLogin, err := getLastLogin(user.Attributes)
			if err != nil {
				return err
			}

			exportUser := ExportUser{
				Username:  *user.Username,
				Email:     getAttribute(user.Attributes, "email"),
				Status:    string(user.UserStatus),
				Enabled:   user.Enabled,
				LastLogin: lastLogin,
			}
			export.Users = append(export.Users, exportUser)
			total++
		}
	}

	export.Total = total
	logger.SetAttr("total_users", total)

	json, err := json.Marshal(export)
	if err != nil {
		return logger.WrapError(err)
	}

	fmt.Print(string(json))

	return nil
}

// getAttribute gets an attribute from the user by attribute name.
func getAttribute(attrs []types.AttributeType, name string) string {
	for _, attr := range attrs {
		if aws.ToString(attr.Name) == name {
			return aws.ToString(attr.Value)
		}
	}
	return ""
}

// getLastLogin gets the last login for the user.
func getLastLogin(attrs []types.AttributeType) (*time.Time, error) {
	value := getAttribute(attrs, "custom:last_login")

	if value == "" {
		return nil, nil
	}

	record := audittypes.LastLogin{}
	err := json.Unmarshal([]byte(value), &record)
	if err != nil {
		return nil, err
	}

	return &record.Time, nil
}
