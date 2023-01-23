package apibee

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"gitlab.cyber-threat-intelligence.com/software/alvarium/bee/pkg/api"
)

const (
	beeStoreFileName  = "bee.store"
	beeStoreFileMode  = 0600
	heartbeatInterval = 1 * time.Minute
)

var ErrBeeConfigNotFound = errors.New("bee config not found")

type BeeConfiguration struct {
	Name string
}

type Bee struct {
	client              *api.Client
	ID                  uuid.UUID `json:"id"`
	AuthenticationToken string    `json:"authentication_token"`
}

func LoadOrRegisterBee(beekeeperBaseURL string) (*Bee, error) {
	bee, err := NewBee(beekeeperBaseURL)
	if err != nil {
		return nil, fmt.Errorf("creating new bee: %w", err)
	}

	if err := bee.loadFromFile(); err != nil {
		if errors.Is(err, ErrBeeConfigNotFound) {
			log.Info("No bee config found")

			var registrationToken string
			fmt.Println("\nRegistering new bee. Please enter the registration token: ")
			if _, err := fmt.Scanln(&registrationToken); err != nil {
				return nil, fmt.Errorf("reading registration token: %w", err)
			}

			if err := bee.register(registrationToken); err != nil {
				return nil, fmt.Errorf("registration: %w", err)
			}

			if err := bee.storeToFile(); err != nil {
				return nil, fmt.Errorf("storing bee to file: %w", err)
			}
		} else {
			return nil, fmt.Errorf("loading configuration from file: %w", err)
		}
	}

	apiKeyProvider, err := securityprovider.NewSecurityProviderApiKey("header", "X-API-KEY", bee.AuthenticationToken)
	if err != nil {
		return nil, fmt.Errorf("creating api key security provider: %w", err)
	}
	bee.client.RequestEditors = append(bee.client.RequestEditors, apiKeyProvider.Intercept)

	return bee, nil
}

func NewBee(beekeeperBasePath string) (*Bee, error) {
	client, err := api.NewClient(beekeeperBasePath)
	if err != nil {
		return nil, fmt.Errorf("creating API client failed: %w", err)
	}

	return &Bee{
		client: client,
	}, nil
}

func (b *Bee) storeToFile() error {
	content, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("marshaling bee failed: %w", err)
	}

	if err := os.WriteFile(beeStoreFileName, content, beeStoreFileMode); err != nil {
		return fmt.Errorf("writing bee store failed: %w", err)
	}
	return nil
}

func (b *Bee) loadFromFile() error {
	content, err := os.ReadFile(beeStoreFileName)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrBeeConfigNotFound
		}
		return fmt.Errorf("opening bee store failed: %w", err)
	}

	if err := json.Unmarshal(content, b); err != nil {
		return fmt.Errorf("unmarshaling bee JSON failed: %w", err)
	}

	return nil
}

func (b *Bee) register(registrationToken string) error {
	ctx := context.Background()
	response, err := b.client.RegisterEndpoint(ctx, api.RegisterEndpointJSONRequestBody{RegistrationToken: registrationToken})
	if err != nil {
		return fmt.Errorf("registering endpoint on API failed: %w", err)
	}

	registerEndpointResponse, err := api.ParseRegisterEndpointResponse(response)
	if err != nil {
		return fmt.Errorf("parsing registration response failed: %w", err)
	}

	if registerEndpointResponse.JSON401 != nil {
		return fmt.Errorf("received 401 from API: %s", registerEndpointResponse.JSON401.Message)
	}

	if registerEndpointResponse.JSON201 == nil {
		return fmt.Errorf("received %d from API: %s", registerEndpointResponse.StatusCode(), registerEndpointResponse.Body)
	}

	b.ID = registerEndpointResponse.JSON201.Id
	b.AuthenticationToken = registerEndpointResponse.JSON201.ApiKey

	authenticationTokenProvider, err := securityprovider.NewSecurityProviderBearerToken(b.AuthenticationToken)
	if err != nil {
		return fmt.Errorf("creating bearer token security provider failed: %w", err)
	}

	b.client.RequestEditors = append(b.client.RequestEditors, authenticationTokenProvider.Intercept)

	return nil
}

func (b *Bee) ReportStats() error {
	ctx := context.Background()
	response, err := b.client.AddEndpointStats(ctx, b.ID, api.AddEndpointStatsJSONRequestBody{})
	if err != nil {
		return fmt.Errorf("reporting stats to beekeeper: %w", err)
	}

	addEndpointStatsResponse, err := api.ParseAddEndpointStatsResponse(response)
	if err != nil {
		return fmt.Errorf("parsing stats reporting response: %w", err)
	}

	if addEndpointStatsResponse.StatusCode() != 204 {
		return fmt.Errorf("received %d from API: %s", addEndpointStatsResponse.StatusCode(), addEndpointStatsResponse.Body)
	}

	return nil
}

func (b *Bee) Name() (string, error) {
	ctx := context.Background()
	response, err := b.client.FindEndpoint(ctx, b.ID)
	if err != nil {
		return "", fmt.Errorf("getting endpoint failed: %w", err)
	}

	findEndpointResponse, err := api.ParseFindEndpointResponse(response)
	if err != nil {
		return "", fmt.Errorf("parsing endpoint response failed: %w", err)
	}

	if code := findEndpointResponse.StatusCode(); code != 200 {
		return "", fmt.Errorf("getting endpoint failed with status code %d: %s", code, findEndpointResponse.Body)
	}

	return findEndpointResponse.JSON200.Name, nil
}

// Heartbeat periodically reports stats to the beehive until ctx is cancelled.
func (b *Bee) Heartbeat(ctx context.Context) error {
	for {
		if err := b.ReportStats(); err != nil {
			log.WithError(err).Warn("Error during heartbeat")
		}

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(heartbeatInterval):
		}
	}
}
