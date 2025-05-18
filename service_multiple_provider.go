package saml

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

type ServiceMultipleProvider struct {
	// Entity ID is optional - if not specified then MetadataURL will be used
	EntityID string

	Providers map[string]ServiceProvider

	// Key is the RSA private key we use to sign requests.
	Key crypto.Signer

	// Certificate is the RSA public part of Key.
	Certificate   *x509.Certificate
	Intermediates []*x509.Certificate

	// HTTPClient to use during SAML artifact resolution
	HTTPClient *http.Client

	// MetadataURL is the full URL to the metadata endpoint on this host,
	// i.e. https://example.com/saml/metadata
	MetadataURL url.URL

	// AcsURL is the full URL to the SAML Assertion Customer Service endpoint
	// on this host, i.e. https://example.com/saml/acs
	AcsURL url.URL

	// SloURL is the full URL to the SAML Single Logout endpoint on this host.
	// i.e. https://example.com/saml/slo
	SloURL url.URL

	// IDPMetadata is the metadata from the identity provider.
	IDPMetadata *EntitiesDescriptor

	// AuthnNameIDFormat is the format used in the NameIDPolicy for
	// authentication requests
	AuthnNameIDFormat NameIDFormat

	// MetadataValidDuration is a duration used to calculate validUntil
	// attribute in the metadata endpoint
	MetadataValidDuration time.Duration

	// ForceAuthn allows you to force re-authentication of users even if the user
	// has a SSO session at the IdP.
	ForceAuthn *bool

	// RequestedAuthnContext allow you to specify the requested authentication
	// context in authentication requests
	RequestedAuthnContext *RequestedAuthnContext

	// AllowIdpInitiated
	AllowIDPInitiated bool

	// DefaultRedirectURI where untracked requests (as of IDPInitiated) are redirected to
	DefaultRedirectURI string

	// SignatureVerifier, if non-nil, allows you to implement an alternative way
	// to verify signatures.
	SignatureVerifier SignatureVerifier

	// SignatureMethod, if non-empty, authentication requests will be signed
	SignatureMethod string

	// LogoutBindings specify the bindings available for SLO endpoint. If empty,
	// HTTP-POST binding is used.
	LogoutBindings []string
}

func (smp *ServiceMultipleProvider) GetServiceProvider(entityID string) (ServiceProvider, error) {
	sp, ok := smp.Providers[entityID]

	if !ok {
		return ServiceProvider{}, fmt.Errorf("no service provider found for entityID %s", entityID)
	}

	return sp, nil
}

func (smp *ServiceMultipleProvider) MakeWayfRedirectionRequest(relayState, returnUrl string) (*url.URL, error) {
	u, err := url.Parse(returnUrl)
	if err != nil {
		return nil, err
	}

	query := u.Query()
	query.Add("rs", relayState)
	u.RawQuery = query.Encode()

	wayfUrl := smp.IDPMetadata.Name

	if wayfUrl == nil {
		return nil, errors.New("identity name is not set")
	}

	wu, err := url.Parse(*wayfUrl)
	if err != nil {
		return nil, err
	}

	query = wu.Query()
	query.Add("return", u.String())
	query.Add("entityID", smp.EntityID)
	wu.RawQuery = query.Encode()

	return wu, nil
}

func (smp *ServiceMultipleProvider) Metadata() *EntityDescriptor {
	validDuration := DefaultValidDuration
	if smp.MetadataValidDuration > 0 {
		validDuration = smp.MetadataValidDuration
	}

	authnRequestsSigned := len(smp.SignatureMethod) > 0
	wantAssertionsSigned := true
	validUntil := TimeNow().Add(validDuration)

	var keyDescriptors []KeyDescriptor
	if smp.Certificate != nil {
		certBytes := smp.Certificate.Raw
		for _, intermediate := range smp.Intermediates {
			certBytes = append(certBytes, intermediate.Raw...)
		}
		keyDescriptors = []KeyDescriptor{
			{
				Use: "encryption",
				KeyInfo: KeyInfo{
					X509Data: X509Data{
						X509Certificates: []X509Certificate{
							{Data: base64.StdEncoding.EncodeToString(certBytes)},
						},
					},
				},
				EncryptionMethods: []EncryptionMethod{
					{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
					{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
					{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
					{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
				},
			},
		}
		if len(smp.SignatureMethod) > 0 {
			keyDescriptors = append(keyDescriptors, KeyDescriptor{
				Use: "signing",
				KeyInfo: KeyInfo{
					X509Data: X509Data{
						X509Certificates: []X509Certificate{
							{Data: base64.StdEncoding.EncodeToString(certBytes)},
						},
					},
				},
			})
		}
	}

	sloEndpoints := make([]Endpoint, len(smp.LogoutBindings))
	for i, binding := range smp.LogoutBindings {
		sloEndpoints[i] = Endpoint{
			Binding:          binding,
			Location:         smp.SloURL.String(),
			ResponseLocation: smp.SloURL.String(),
		}
	}

	return &EntityDescriptor{
		EntityID:   firstSet(smp.EntityID, smp.MetadataURL.String()),
		ValidUntil: validUntil,

		SPSSODescriptors: []SPSSODescriptor{
			{
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors:             keyDescriptors,
						ValidUntil:                 &validUntil,
					},
					SingleLogoutServices: sloEndpoints,
					NameIDFormats:        []NameIDFormat{smp.AuthnNameIDFormat},
				},
				AuthnRequestsSigned:  &authnRequestsSigned,
				WantAssertionsSigned: &wantAssertionsSigned,

				AssertionConsumerServices: []IndexedEndpoint{
					{
						Binding:  HTTPPostBinding,
						Location: smp.AcsURL.String(),
						Index:    1,
					},
					{
						Binding:  HTTPArtifactBinding,
						Location: smp.AcsURL.String(),
						Index:    2,
					},
				},
			},
		},
	}
}
