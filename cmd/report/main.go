package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"mime"
	"mime/multipart"
	"net/textproto"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sestypes "github.com/aws/aws-sdk-go-v2/service/sesv2/types"
	"github.com/caarlos0/env/v11"
	"github.com/skpr/yolog"

	audittypes "github.com/skpr/cognito-audit/internal/types"
)

const (
	// YoLogStream is the log stream name for yolog logs.
	YoLogStream = "cognito-audit-report"

	// ReportAttachmentName is the filename used for the JSON report
	// attachment on the outgoing email.
	ReportAttachmentName = "user-audit-report.json"

	// ReportEmailSubject is the subject line used for the outgoing email.
	ReportEmailSubject = "User Audit Report"
)

// Config is the environment based configuration for this lambda.
type Config struct {
	// UserPoolID is the ID of the Cognito user pool to report on.
	UserPoolID string `env:"COGNITO_USER_POOL_ID,required"`
	// ReportEmailFrom is the "From" address used when sending the report
	// via SES. This address must be verified in SES.
	ReportEmailFrom string `env:"REPORT_EMAIL_FROM,required"`
	// ReportEmailTo is the address the report email is sent to.
	ReportEmailTo string `env:"REPORT_EMAIL_TO,required"`
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
	Groups    []string   `json:"groups"`
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

	cognitoClient := cognitoidentityprovider.NewFromConfig(awsConfig)
	sesClient := sesv2.NewFromConfig(awsConfig)

	err = run(ctx, logger, cognitoClient, sesClient, lambdaConfig)
	if err != nil {
		return logger.WrapError(err)
	}

	return nil
}

// run reads all users from the configured Cognito user pool, paginating
// through the full result set, and emails the resulting JSON report as an
// attachment via Amazon SES.
func run(ctx context.Context, logger *yolog.Logger, cognitoClient *cognitoidentityprovider.Client, sesClient *sesv2.Client, config Config) error {
	paginator := cognitoidentityprovider.NewListUsersPaginator(cognitoClient, &cognitoidentityprovider.ListUsersInput{
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

			groups, err := getGroups(ctx, cognitoClient, config.UserPoolID, *user.Username)
			if err != nil {
				return err
			}

			exportUser := ExportUser{
				Username:  *user.Username,
				Email:     getAttribute(user.Attributes, "email"),
				Status:    string(user.UserStatus),
				Enabled:   user.Enabled,
				LastLogin: lastLogin,
				Groups:    groups,
			}
			export.Users = append(export.Users, exportUser)
			total++
		}
	}

	export.Total = total
	logger.SetAttr("total_users", total)

	reportJSON, err := json.Marshal(export)
	if err != nil {
		return logger.WrapError(err)
	}

	rawMessage, err := buildEmail(config.ReportEmailFrom, config.ReportEmailTo, ReportEmailSubject, reportJSON)
	if err != nil {
		return logger.WrapError(err)
	}

	_, err = sesClient.SendEmail(ctx, &sesv2.SendEmailInput{
		FromEmailAddress: aws.String(config.ReportEmailFrom),
		Destination: &sestypes.Destination{
			ToAddresses: []string{config.ReportEmailTo},
		},
		Content: &sestypes.EmailContent{
			Raw: &sestypes.RawMessage{
				Data: rawMessage,
			},
		},
	})
	if err != nil {
		return logger.WrapError(err)
	}

	logger.SetAttr("report_email_to", config.ReportEmailTo)

	return nil
}

// buildEmail constructs a raw MIME email with the provided JSON report
// attached as a file, suitable for sending via SES's raw message API.
func buildEmail(from, to, subject string, attachment []byte) ([]byte, error) {
	var buf bytes.Buffer

	writer := multipart.NewWriter(&buf)

	fmt.Fprintf(&buf, "From: %s\r\n", from)
	fmt.Fprintf(&buf, "To: %s\r\n", to)
	fmt.Fprintf(&buf, "Subject: %s\r\n", mime.QEncoding.Encode("UTF-8", subject))
	fmt.Fprint(&buf, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&buf, "Content-Type: multipart/mixed; boundary=%q\r\n", writer.Boundary())
	fmt.Fprint(&buf, "\r\n")

	bodyPart, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Type": {"text/plain; charset=UTF-8"},
	})
	if err != nil {
		return nil, err
	}
	_, err = bodyPart.Write([]byte("Please find the attached user report.\r\n"))
	if err != nil {
		return nil, err
	}

	attachmentPart, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {"application/json"},
		"Content-Transfer-Encoding": {"base64"},
		"Content-Disposition":       {fmt.Sprintf(`attachment; filename=%q`, ReportAttachmentName)},
	})
	if err != nil {
		return nil, err
	}

	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(attachment)))
	base64.StdEncoding.Encode(encoded, attachment)

	_, err = attachmentPart.Write(encoded)
	if err != nil {
		return nil, err
	}

	err = writer.Close()
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
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

// getGroups returns the names of the Cognito groups that the given user
// belongs to, paginating through the full result set.
func getGroups(ctx context.Context, cognitoClient *cognitoidentityprovider.Client, userPoolID, username string) ([]string, error) {
	paginator := cognitoidentityprovider.NewAdminListGroupsForUserPaginator(cognitoClient, &cognitoidentityprovider.AdminListGroupsForUserInput{
		UserPoolId: aws.String(userPoolID),
		Username:   aws.String(username),
	})

	var groups []string

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, group := range page.Groups {
			groups = append(groups, aws.ToString(group.GroupName))
		}
	}

	return groups, nil
}
