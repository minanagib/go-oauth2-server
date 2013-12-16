package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)


// ----------------------------------------------------------------------------


// Store [...]
type Store interface {
	// A Client is always returned -- it is nil only if ClientID is invalid.
	// Use the error to indicate denied or unauthorized access.
	GetClient(clientID string) (Client, error)
	GetClientByCode(code string) (Client, error)
	CreateAuthCode(r AuthCodeRequest) (string, error)
        CreateAccessToken(r AccessTokenRequest) (string, error)
        CreateRefreshToken(r AccessTokenRequest) (string, error)
}

// ----------------------------------------------------------------------------

// Client is a client registered with the authorization server.
type Client interface {
	// Unique identifier for the client.
	ID() string
	// The registered client type ("confidential" or "public") as decribed in:
	// http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-2.1
	Type() string
	// The registered redirect_uri.
	RedirectURI() string
	// Validates that the provided redirect_uri is valid. It must return the
	// same provided URI or an empty string if it is not valid.
	// The specification is permissive and even allows multiple URIs, so the
	// validation rules are up to the server implementation.
	// Ref: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-3.1.2.2
	ValidateRedirectURI(string) string
	// Access token returned in exchange for the code
	AccessToken() string
	// Refresh token to renew Access token
	RefreshToken() string
}



type CrowdSurgeClient struct{	
	clientId string
	clientType string
	redirectURI string
	validateRedirectURI string	
	accessToken string
	refreshToken string
}

func (client *CrowdSurgeClient) ID() string{
	return client.clientId
}

func (client *CrowdSurgeClient) Type() string{
	return client.clientType
}

func (client *CrowdSurgeClient) RedirectURI() string{
	return client.redirectURI
}

func (client *CrowdSurgeClient) ValidateRedirectURI(uri string) string{
	return client.validateRedirectURI
}

func (client *CrowdSurgeClient) AccessToken() string{
	return client.accessToken
}

func (client *CrowdSurgeClient) RefreshToken() string{
	return client.refreshToken
}


// ----------------------------------------------------------------------------

// AuthCodeRequest [...]
type AuthCodeRequest struct {
	ClientID     string
	ResponseType string
	RedirectURI  string
	Scope        string
	State        string
}

// AccessTokenRequest [...]
type AccessTokenRequest struct {
	GrantType   string
	Code        string
	RedirectURI string
}

// ----------------------------------------------------------------------------


// ------------------- DEFINE A MONGODB Store ---------------------------------
type MongoDBStore struct{


}

func (mdb *MongoDBStore) GetClient(clientID string) (Client, error){
	var error error
	client := &CrowdSurgeClient{clientId: "123456", clientType: "confidential", redirectURI: "http://localhost", validateRedirectURI: "http://localhost"}
	return client, error

}

func (mdb *MongoDBStore) GetClientByCode(code string) (Client, error){
	var error error
	client := &CrowdSurgeClient{clientId: "123456", clientType: "confidential", redirectURI: "http://localhost", validateRedirectURI: "http://localhost"}
	return client, error

}

func (mdb *MongoDBStore) CreateAuthCode(r AuthCodeRequest) (string, error){
	var error error
	salt := time.Now().UTC().Nanosecond()
	strSalt := string(salt)
	data := []byte(strSalt + "this is an awesomly long code. we should try to make it longer")
	code := base64.StdEncoding.EncodeToString(data)
	fmt.Println(code)
	return code, error
}

func (mdb *MongoDBStore) CreateAccessToken(r AccessTokenRequest)(string, error){
	var error error
	salt := time.Now().UTC().Nanosecond()
	strSalt := string(salt)
	data := []byte(strSalt + "this is your access token. we should try to make it longer")
	// Create Access Token
	accessToken := base64.StdEncoding.EncodeToString(data)
	return accessToken, error

}

func (mdb *MongoDBStore) CreateRefreshToken(r AccessTokenRequest) (string, error){
	var error error
	// Create Refresh Token
	salt := time.Now().UTC().Nanosecond()
	strSalt := string(salt)
	data := []byte(strSalt + "this is your refresh. we should try to make it longer")
	refreshToken := base64.StdEncoding.EncodeToString(data)
	return refreshToken, error
}
// NewServer [...]
func NewServer() *Server {
	return &Server{
		errorURIs: make(map[errorCode]string),
	}
}

// Server [...]
type Server struct {
	Store     Store
	errorURIs map[errorCode]string
}

// RegisterErrorURI [...]
func (s *Server) RegisterErrorURI(code errorCode, uri string) {
	s.errorURIs[code] = uri
}

// NewError [...]
func (s *Server) NewError(code errorCode, description string) ServerError {
	return NewServerError(code, description, s.errorURIs[code])

}
// NewAuthCodeRequest [...]
func (s *Server) NewAuthCodeRequest(r *http.Request) AuthCodeRequest {
	v := r.URL.Query()
	fmt.Println(v)
	return AuthCodeRequest{
		ClientID:     v.Get("client_id"),
		ResponseType: v.Get("response_type"),
		RedirectURI:  v.Get("redirect_uri"),
		Scope:        v.Get("scope"),
		State:        v.Get("state"),
	}
}

// NewAccessTokenRequest [...]
func (s *Server) NewAccessTokenRequest(r *http.Request) AccessTokenRequest {
	v := r.URL.Query()
	fmt.Println(v)
	return AccessTokenRequest{
		RedirectURI:  v.Get("redirect_uri"),
		Code:         v.Get("code"),
		GrantType:    v.Get("grant_type"),
	}
}

// HandleAuthCodeRequest [...]
func (s *Server) HandleAuthCodeRequest(w http.ResponseWriter, r *http.Request) error {
	// 1. Get all request values.
	req := s.NewAuthCodeRequest(r)
	fmt.Println("Reqs", req)
	// 2. Validate required parameters.
	var err error
	if req.ClientID == "" {
		// Missing ClientID: no redirect.
		err = s.NewError(ErrorCodeInvalidRequest,
			"The \"client_id\" parameter is missing.")
	} else if req.ResponseType == "" {
		err = s.NewError(ErrorCodeInvalidRequest,
			"The \"response_type\" parameter is missing.")
	} else if req.ResponseType != "code" {
		err = s.NewError(ErrorCodeUnsupportedResponseType,
			fmt.Sprintf("The response type %q is not supported.",
			req.ResponseType))
	}
	// 3. Load client and validate the redirection URI.
	var redirectURI *url.URL
	if req.ClientID != "" {
		client, clientErr := s.Store.GetClient(req.ClientID)
		if client == nil {
			// Invalid ClientID: no redirect.
			if err == nil {
				err = s.NewError(ErrorCodeInvalidRequest,
					"The \"client_id\" parameter is invalid.")
			}
			fmt.Println("bad client id")
		} else {
			if u, uErr := validateRedirectURI(
				client.ValidateRedirectURI(req.RedirectURI)); uErr == nil {
				redirectURI = u
			} else {
				// Missing, mismatching or invalid URI: no redirect.
				if err == nil {
					if req.RedirectURI == "" {
						err = s.NewError(ErrorCodeInvalidRequest,
							"Missing redirection URI.")
					} else {
						err = s.NewError(ErrorCodeInvalidRequest, uErr.Error())
					}
				}
			}
			if clientErr != nil && err == nil {
				// Client was not authorized.
				err = clientErr
			}
		}
	}

	// 4. If no valid redirection URI was set, abort.
	if redirectURI == nil {
		// An error occurred because client_id or redirect_uri are invalid:
		// the caller must display an error page and don't redirect.
		return err
	}

	// 5. Add the response data to the URL and redirect.
	query := redirectURI.Query()
	setQueryPairs(query, "state", req.State)
	var code string
	if err == nil {
		code, err = s.Store.CreateAuthCode(req)
	}
	if err == nil {
		// Success.
		query.Set("code", code)
	} else {
		e, ok := err.(ServerError)
		if !ok {
			e = s.NewError(ErrorCodeServerError, e.Error())
		}
		setQueryPairs(query,
			"error", string(e.Code()),
			"error_description", e.Description(),
			"error_uri", e.URI(),
		)
	}
	redirectURI.RawQuery = query.Encode()
	//http.Redirect(w, r, redirectURI.String(), 302)
	fmt.Fprint(w, "Access Code: " + code)
	return nil
}

// HandleAccessTokenRequest [...]
func (s *Server) HandleAccessTokenRequest(w http.ResponseWriter, r *http.Request) error {
	// 1. Get all request values.
	req := s.NewAccessTokenRequest(r)
	fmt.Println("Reqs", req)
	// 2. Validate required parameters.
	var err error
	if req.Code == "" {
		// Missing Code: no redirect.
		err = s.NewError(ErrorCodeInvalidRequest,
			"The \"code\" parameter is missing.")
	} else if req.GrantType != "authorization_code" {
		err = s.NewError(ErrorCodeInvalidRequest,
			"The \"grant_type\" parameter is invalid.")
	} else if req.RedirectURI == "" {
		err = s.NewError(ErrorCodeUnsupportedResponseType,
			"The \"redirect_uri\" parameter is missing")
	}
	// 3. Load client and validate the redirection URI.
	var redirectURI *url.URL
	if req.Code != "" {
		client, clientErr := s.Store.GetClientByCode(req.Code)
		if client == nil {
			// Invalid ClientID: no redirect.
			if err == nil {
				err = s.NewError(ErrorCodeInvalidRequest,
					"The \"client_id\" parameter is invalid.")
			}
			fmt.Println("bad client id")
		} else {
			if u, uErr := validateRedirectURI(
				client.ValidateRedirectURI(req.RedirectURI)); uErr == nil {
				redirectURI = u
			} else {
				// Missing, mismatching or invalid URI: no redirect.
				if err == nil {
					if req.RedirectURI == "" {
						err = s.NewError(ErrorCodeInvalidRequest,
							"Missing redirection URI.")
					} else {
						err = s.NewError(ErrorCodeInvalidRequest, uErr.Error())
					}
				}
			}
			if clientErr != nil && err == nil {
				// Client was not authorized.
				err = clientErr
			}
		}
	}

	// 4. If no valid redirection URI was set, abort.
	if redirectURI == nil {
		// An error occurred because client_id or redirect_uri are invalid:
		// the caller must display an error page and don't redirect.
		return err
	}

	// 5. Add the response data to the URL and redirect.
	query := redirectURI.Query()
	//setQueryPairs(query, "state", req.State)
	var accessToken, refreshToken string
	if err == nil {
		accessToken, err = s.Store.CreateAccessToken(req)
		refreshToken, err = s.Store.CreateRefreshToken(req)
	}
	if err == nil {
		// Success.
		query.Set("access_token", accessToken)
		query.Set("refresh_token", refreshToken)
	} else {
		e, ok := err.(ServerError)
		if !ok {
			e = s.NewError(ErrorCodeServerError, e.Error())
		}
		setQueryPairs(query,
			"error", string(e.Code()),
			"error_description", e.Description(),
			"error_uri", e.URI(),
		)
	}
	redirectURI.RawQuery = query.Encode()
	//http.Redirect(w, r, redirectURI.String(), 302)
        response := make(map[string]string)
	response["access_token"] = accessToken
	response["refresh_token"] = refreshToken
	response["token_type"] = "bearer"
	output, _ := json.MarshalIndent(response, "", " ")
	fmt.Fprint(w, string(output))
	return nil
}

// ----------------------------------------------------------------------------

// setQueryPairs sets non-empty values in a url.Values.
//
// This is just a convenience to avoid checking for emptiness for each value.
func setQueryPairs(v url.Values, pairs ...string) {
	for i := 0; i < len(pairs); i += 2 {
		if pairs[i+1] != "" {
			v.Set(pairs[i], pairs[i+1])
		}
	}
}

// validateRedirectURI checks if a redirection URL is valid.
func validateRedirectURI(uri string) (u *url.URL, err error) {
	u, err = url.Parse(uri)
	if err != nil {
		err = fmt.Errorf("The redirection URI is malformed: %q.", uri)
	} else if !u.IsAbs() {
		err = fmt.Errorf("The redirection URI must be absolute: %q.", uri)
	} else if u.Fragment != "" {
		err = fmt.Errorf(
			"The redirection URI must not contain a fragment: %q.", uri)
	}
	return
}

// randomString generates authorization codes or tokens with a given strength.
func randomString(strength int) string {
	s := make([]byte, strength)
	if _, err := rand.Read(s); err != nil {
		return ""
	}
	return strings.TrimRight(base64.URLEncoding.EncodeToString(s), "=")
}
