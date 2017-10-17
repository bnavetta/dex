// Package slack provides authentication strategies using Slack.
package slack

import (
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/slack"

	"errors"
	"github.com/coreos/dex/connector"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"gopkg.in/square/go-jose.v2/json"
	"io/ioutil"
	"net/http"
)

const (
	scopeBasic = "identity.basic"
	scopeEmail = "identity.email"
	scopeTeam  = "identity.team"
)

type Config struct {
	ClientID     string   `json:"clientID"`
	ClientSecret string   `json:"clientSecret"`
	RedirectURI  string   `json:"redirectURI"`
	Teams        []string `json:"teams",omitempty`
}

func (c *Config) Open(logger logrus.FieldLogger) (connector.Connector, error) {
	s := slackConnector{
		redirectURI:  c.RedirectURI,
		clientID:     c.ClientID,
		clientSecret: c.ClientSecret,
		teams:        c.Teams,
		logger:       logger,
	}

	return &s, nil
}

type connectorData struct {
	AccessToken string `json:"accessToken"`
}

type slackConnector struct {
	redirectURI  string
	clientID     string
	clientSecret string
	teams        []string
	logger       logrus.FieldLogger
}

// teamsRequired returns whether dex requires Slack's 'identity.team' scope. Dex
// needs 'identity.team' if the 'teams' field is populated in a config file.
// Clients can require the 'groups' scope without setting 'teams'.
func (c *slackConnector) teamsRequired(groupScope bool) bool {
	return len(c.teams) > 0 || groupScope
}

func (c *slackConnector) oauth2Config(scopes connector.Scopes) *oauth2.Config {
	slackScopes := []string{scopeBasic, scopeEmail}
	if c.teamsRequired(scopes.Groups) {
		slackScopes = append(slackScopes, scopeTeam)
	}

	endpoint := slack.Endpoint

	return &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint:     endpoint,
		Scopes:       slackScopes,
	}
}

func (c *slackConnector) LoginURL(scopes connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL %q did not match the URL in the config %q", callbackURL, c.redirectURI)
	}

	return c.oauth2Config(scopes).AuthCodeURL(state), nil
}

func (c *slackConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, errors.New(errType)
	}

	oauth2Config := c.oauth2Config(s)

	ctx := r.Context()

	token, err := oauth2Config.Exchange(ctx, q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("slack: failed to get token: %v", err)
	}

	client := oauth2Config.Client(ctx, token)

	ident, err := c.identity(ctx, client)
	if err != nil {
		return identity, fmt.Errorf("slack: get identity: %v", err)
	}

	identity = connector.Identity{
		UserID:        ident.User.ID,
		Username:      ident.User.Name,
		Email:         ident.User.Email,
		EmailVerified: true,
	}

	if c.teamsRequired(s.Groups) {
		identity.Groups = []string{ident.Team.Name, ident.Team.Id, ident.Team.Domain}
	}

	if s.OfflineAccess {
		data := connectorData{AccessToken: token.AccessToken}
		connData, err := json.Marshal(data)
		if err != nil {
			return identity, fmt.Errorf("marshal connector data: %v", err)
		}
		identity.ConnectorData = connData
	}

	return identity, nil
}

func (c *slackConnector) Refresh(ctx context.Context, s connector.Scopes, identity connector.Identity) (connector.Identity, error) {
	if len(identity.ConnectorData) == 0 {
		return identity, errors.New("no upstream access token found")
	}

	var data connectorData
	if err := json.Unmarshal(identity.ConnectorData, &data); err != nil {
		return identity, fmt.Errorf("slack: unmarshal access token: %v", err)
	}

	client := c.oauth2Config(s).Client(ctx, &oauth2.Token{AccessToken: data.AccessToken})
	ident, err := c.identity(ctx, client)
	if err != nil {
		return identity, fmt.Errorf("slack: get identity: %v", err)
	}

	identity.Username = ident.User.Name
	identity.Email = ident.User.Email

	if c.teamsRequired(s.Groups) {
		identity.Groups = []string{ident.Team.Name, ident.Team.Id, ident.Team.Domain}
	}

	return identity, nil
}

func (c *slackConnector) identity(ctx context.Context, client *http.Client) (identity, error) {
	// https://api.slack.com/docs/sign-in-with-slack#using_tokens_to_retrieve_user_and_team_information
	var i identity

	req, err := http.NewRequest("GET", "https://slack.com/api/users.identity", nil)
	if err != nil {
		return i, fmt.Errorf("slack: new req: %v", err)
	}

	req = req.WithContext(ctx)
	resp, err := client.Do(req)
	if err != nil {
		return i, fmt.Errorf("slack: get URL %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return i, fmt.Errorf("slack: read body: %v", err)
		}
		return i, fmt.Errorf("%s: %s", resp.Status, body)
	}

	if err := json.NewDecoder(resp.Body).Decode(&i); err != nil {
		return i, fmt.Errorf("slack: failed to decode response: %v", err)
	}

	return i, nil
}

type identity struct {
	User user `json:"user"`
	Team team `json:"team"`
}

type user struct {
	Name  string `json:"name"`
	ID    string `json:"id"`
	Email string `json:"email"`
}

type team struct {
	Id     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
}
