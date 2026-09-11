package main

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/caarlos0/env/v11"
	"github.com/skpr/yolog"
)

const (
	// YoLogStream is the log stream name for yolog logs.
	YoLogStream = "cognito-audit-login"
)

type Config struct {
	// CustomAttribute is the name of the custom user pool attribute that will
	// be updated with the last login metadata. Custom attributes must be
	// prefixed with "custom:" when referenced via the Cognito API.
	CustomAttribute string `env:"COGNITO_LAST_LOGIN_ATTRIBUTE" envDefault:"custom:last_login"`
}

// LastLogin is the JSON payload that is stored in the custom user pool
// attribute every time a user successfully authenticates.
type LastLogin struct {
	// Time the user last logged in, in RFC3339 format.
	Time string `json:"time"`
	// ClientID of the app client that was used to authenticate.
	ClientID string `json:"client_id,omitempty"`
}

func main() {
	lambda.Start(handler)
}

// Start is an exported abstraction so that the application can be
// setup in a way that works for you, opposed to being a tightly
// coupled to provided and assumed Clients.
func handler(ctx context.Context, event events.CognitoEventUserPoolsPostAuthentication) (events.CognitoEventUserPoolsPostAuthentication, error) {
	logger := yolog.NewLogger(YoLogStream)
	defer logger.Log(os.Stdout)

	logger.SetAttrs("user_pool_id", event.UserPoolID, "username", event.UserName, "client_id", event.CallerContext.ClientID)

	var lambdaConfig Config

	err := env.Parse(&lambdaConfig)
	if err != nil {
		return event, logger.WrapError(err)
	}

	awsConfig, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return event, logger.WrapError(err)
	}

	client := cognitoidentityprovider.NewFromConfig(awsConfig)

	err = run(ctx, logger, client, lambdaConfig, event)
	if err != nil {
		return event, logger.WrapError(err)
	}

	return event, nil
}

// run updates the authenticated user's custom attribute with a JSON payload
// describing their most recent login.
func run(ctx context.Context, logger *yolog.Logger, client *cognitoidentityprovider.Client, config Config, event events.CognitoEventUserPoolsPostAuthentication) error {
	payload, err := json.Marshal(LastLogin{
		Time:     time.Now().UTC().Format(time.RFC3339),
		ClientID: event.CallerContext.ClientID,
	})
	if err != nil {
		return err
	}

	value := string(payload)

	_, err = client.AdminUpdateUserAttributes(ctx, &cognitoidentityprovider.AdminUpdateUserAttributesInput{
		UserPoolId: &event.UserPoolID,
		Username:   &event.UserName,
		UserAttributes: []types.AttributeType{
			{
				Name:  &config.CustomAttribute,
				Value: &value,
			},
		},
	})
	if err != nil {
		return err
	}

	logger.SetAttr("last_login", value)

	return nil
}
