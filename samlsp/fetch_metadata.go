package samlsp

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	xrv "github.com/mattermost/xml-roundtrip-validator"

	"github.com/insaplace/saml/logger"

	"github.com/insaplace/saml"
)

// ParseMetadata parses arbitrary SAML IDP metadata.
//
// Note: this is needed because IDP metadata is sometimes wrapped in
// an <EntitiesDescriptor>, and sometimes the top level element is an
// <EntityDescriptor>.
func ParseMetadata(data []byte) (*saml.EntityDescriptor, error) {
	entity := &saml.EntityDescriptor{}

	if err := xrv.Validate(bytes.NewBuffer(data)); err != nil {
		return nil, err
	}

	err := xml.Unmarshal(data, entity)

	// this comparison is ugly, but it is how the error is generated in encoding/xml
	if err != nil && err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
		entities := &saml.EntitiesDescriptor{}
		if err := xml.Unmarshal(data, entities); err != nil {
			return nil, err
		}

		for i, e := range entities.EntityDescriptors {
			if len(e.IDPSSODescriptors) > 0 {
				return &entities.EntityDescriptors[i], nil
			}
		}
		return nil, errors.New("no entity found with IDPSSODescriptor")
	}
	if err != nil {
		return nil, err
	}
	return entity, nil
}

func ParseEntitiesMetadata(data []byte) (*saml.EntitiesDescriptor, error) {
	entities := &saml.EntitiesDescriptor{}
	if err := xrv.Validate(bytes.NewBuffer(data)); err != nil {
		return nil, err
	}

	err := xml.Unmarshal(data, entities)
	// this comparison is ugly, but it is how the error is generated in encoding/xml
	if err != nil && err.Error() == "expected element type <EntitiesDescriptor> but have <EntityDescriptor>" {
		entity := &saml.EntityDescriptor{}
		if err := xml.Unmarshal(data, entity); err != nil {
			return nil, err
		}

		entities.EntityDescriptors = []saml.EntityDescriptor{*entity}
		return entities, nil
	}
	if err != nil {
		return nil, err
	}
	return entities, nil
}

// FetchMetadata returns metadata from an IDP metadata URL.
// Deprecated: use FetchEntityMetatada or FetchEntitiesMetadata instead.
func FetchMetadata(ctx context.Context, httpClient *http.Client, metadataURL url.URL) (*saml.EntityDescriptor, error) {
	return fetchMetadata(ctx, httpClient, metadataURL, ParseMetadata)
}

func fetchMetadata[R *saml.EntityDescriptor | *saml.EntitiesDescriptor](ctx context.Context, httpClient *http.Client, metadataURL url.URL, f func(data []byte) (R, error)) (R, error) {
	req, err := http.NewRequest("GET", metadataURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.DefaultLogger.Printf("Error while closing response body during fetch metadata: %v", err)
		}
	}()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("failed to fetch metadata: unexpected status code %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return f(data)
}

func FetchEntityMetatada(ctx context.Context, httpClient *http.Client, metadataURL url.URL) (*saml.EntityDescriptor, error) {
	return fetchMetadata(ctx, httpClient, metadataURL, ParseMetadata)
}

func FetchEntitiesMetadata(ctx context.Context, httpClient *http.Client, metadataURL url.URL) (*saml.EntitiesDescriptor, error) {
	return fetchMetadata(ctx, httpClient, metadataURL, ParseEntitiesMetadata)
}
