package apibee

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/google/uuid"
	"gitlab.cyber-threat-intelligence.com/software/alvarium/bee/pkg/api"
)

const (
	beeStoreFileName = "bee.store"
	beeStoreFileMode = 0600
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

func NewBee(beekeeperBasePath string) (*Bee, error) {
	client, err := api.NewClient(beekeeperBasePath)
	if err != nil {
		return nil, fmt.Errorf("creating API client failed: %w", err)
	}

	return &Bee{
		client: client,
	}, nil
}

func (b *Bee) StoreToFile() error {
	content, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("marshaling bee failed: %w", err)
	}

	if err := os.WriteFile(beeStoreFileName, content, beeStoreFileMode); err != nil {
		return fmt.Errorf("writing bee store failed: %w", err)
	}
	return nil
}

func (b *Bee) LoadFromFile() error {
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

func (b *Bee) Register(registrationToken string) error {
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
	b.AuthenticationToken = registerEndpointResponse.JSON201.AuthenticationToken

	authenticationTokenProvider, err := securityprovider.NewSecurityProviderBearerToken(b.AuthenticationToken)
	if err != nil {
		return fmt.Errorf("creating bearer token security provider failed: %w", err)
	}

	b.client.RequestEditors = append(b.client.RequestEditors, authenticationTokenProvider.Intercept)

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
