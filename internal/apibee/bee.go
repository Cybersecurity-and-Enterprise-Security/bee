package apibee

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/Cybersecurity-and-Enterprise-Security/bee/internal/version"
	"github.com/Cybersecurity-and-Enterprise-Security/bee/pkg/api"
	"github.com/deepmap/oapi-codegen/pkg/securityprovider"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
	WireGuardIP         string    `json:"wireguard_ip"`
	WireGuardPrivateKey string    `json:"wireguard_private_key"`
	BeehiveIPRange      string    `json:"beehive_iprange"`
}

func LoadOrRegisterBee(beekeeperBaseURL string) (*Bee, error) {
	bee, err := NewBee(beekeeperBaseURL)
	if err != nil {
		return nil, fmt.Errorf("creating new bee: %w", err)
	}

	if err := bee.loadFromFile(); err != nil {
		if errors.Is(err, ErrBeeConfigNotFound) {
			log.Info("No bee config found, registering new bee.")

			registrationToken := os.Getenv("BEE_REGISTRATION_TOKEN")

			if registrationToken != "" {
				log.Info("Read registration token from environment.")
			} else {
				fmt.Println("Please enter the registration token: ")
				if _, err := fmt.Scanln(&registrationToken); err != nil {
					return nil, fmt.Errorf("reading registration token: %w", err)
				}
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
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generating new wireguard private key: %w", err)
	}

	ctx := context.Background()
	response, err := b.client.RegisterNewEndpoint(ctx, api.RegisterEndpointRequest{
		RegistrationToken:  registrationToken,
		WireguardPublicKey: key.PublicKey().String(),
	})
	if err != nil {
		return fmt.Errorf("registering endpoint on API failed: %w", err)
	}

	registerEndpointResponse, err := api.ParseRegisterNewEndpointResponse(response)
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
	b.WireGuardIP = registerEndpointResponse.JSON201.WireguardIP
	b.WireGuardPrivateKey = key.String()
	b.BeehiveIPRange = registerEndpointResponse.JSON201.BeehiveIPRange

	return nil
}

func (b *Bee) Startup(ctx context.Context) error {
	response, err := b.client.StartEndpoint(ctx, b.ID, api.EndpointStartup{Version: version.VERSION})
	if err != nil {
		return fmt.Errorf("reporting startup to beekeeper: %w", err)
	}

	startEndpointResponse, err := api.ParseStartEndpointResponse(response)
	if err != nil {
		return fmt.Errorf("parsing start endpoint response: %w", err)
	}

	if startEndpointResponse.StatusCode() != 204 {
		return fmt.Errorf("endpoint startup received %d from API: %s", startEndpointResponse.StatusCode(), startEndpointResponse.Body)
	}

	return nil
}

func (b *Bee) ReportStatistics(ctx context.Context, bindAddress string) error {
	response, err := b.client.AddEndpointStatistics(ctx, b.ID, api.EndpointStatistics{Ip: bindAddress})
	if err != nil {
		return fmt.Errorf("reporting stats to beekeeper: %w", err)
	}

	addEndpointStatsResponse, err := api.ParseAddEndpointStatisticsResponse(response)
	if err != nil {
		return fmt.Errorf("parsing stats reporting response: %w", err)
	}

	// We ignore the 429 here because this may happen if the bee is restarted frequently. To not confuse users,
	// we ignore the error here and don't propagate.
	if addEndpointStatsResponse.StatusCode() != 204 && addEndpointStatsResponse.StatusCode() != 429 {
		return fmt.Errorf("received %d from API: %s", addEndpointStatsResponse.StatusCode(), addEndpointStatsResponse.Body)
	}

	return nil
}

func (b *Bee) GetForwardingInformation(ctx context.Context) (*api.EndpointForwardingInformation, error) {
	response, err := b.client.GetEndpointForwardingInformation(ctx, b.ID)
	if err != nil {
		return nil, fmt.Errorf("getting forwarding information: %w", err)
	}
	parsedResponse, err := api.ParseGetEndpointForwardingInformationResponse(response)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint forwarding information response: %w", err)
	}
	if parsedResponse.StatusCode() != 200 || parsedResponse.JSON200 == nil {
		return nil, fmt.Errorf("received %d from API: %s", parsedResponse.StatusCode(), parsedResponse.Body)
	}
	return parsedResponse.JSON200, nil
}

func (b *Bee) Name(ctx context.Context) (string, error) {
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
