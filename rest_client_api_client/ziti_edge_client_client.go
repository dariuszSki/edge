// Code generated by go-swagger; DO NOT EDIT.

//
// Copyright NetFoundry, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// __          __              _
// \ \        / /             (_)
//  \ \  /\  / /_ _ _ __ _ __  _ _ __   __ _
//   \ \/  \/ / _` | '__| '_ \| | '_ \ / _` |
//    \  /\  / (_| | |  | | | | | | | | (_| | : This file is generated, do not edit it.
//     \/  \/ \__,_|_|  |_| |_|_|_| |_|\__, |
//                                      __/ |
//                                     |___/

package rest_client_api_client

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_client_api_client/authentication"
	"github.com/openziti/edge/rest_client_api_client/current_api_session"
	"github.com/openziti/edge/rest_client_api_client/current_identity"
	"github.com/openziti/edge/rest_client_api_client/enroll"
	"github.com/openziti/edge/rest_client_api_client/external_jwt_signer"
	"github.com/openziti/edge/rest_client_api_client/informational"
	"github.com/openziti/edge/rest_client_api_client/posture_checks"
	"github.com/openziti/edge/rest_client_api_client/service"
	"github.com/openziti/edge/rest_client_api_client/session"
	"github.com/openziti/edge/rest_client_api_client/well_known"
)

// Default ziti edge client HTTP client.
var Default = NewHTTPClient(nil)

const (
	// DefaultHost is the default Host
	// found in Meta (info) section of spec file
	DefaultHost string = "demo.ziti.dev"
	// DefaultBasePath is the default BasePath
	// found in Meta (info) section of spec file
	DefaultBasePath string = "/edge/client/v1"
)

// DefaultSchemes are the default schemes found in Meta (info) section of spec file
var DefaultSchemes = []string{"https"}

// NewHTTPClient creates a new ziti edge client HTTP client.
func NewHTTPClient(formats strfmt.Registry) *ZitiEdgeClient {
	return NewHTTPClientWithConfig(formats, nil)
}

// NewHTTPClientWithConfig creates a new ziti edge client HTTP client,
// using a customizable transport config.
func NewHTTPClientWithConfig(formats strfmt.Registry, cfg *TransportConfig) *ZitiEdgeClient {
	// ensure nullable parameters have default
	if cfg == nil {
		cfg = DefaultTransportConfig()
	}

	// create transport and client
	transport := httptransport.New(cfg.Host, cfg.BasePath, cfg.Schemes)
	return New(transport, formats)
}

// New creates a new ziti edge client client
func New(transport runtime.ClientTransport, formats strfmt.Registry) *ZitiEdgeClient {
	// ensure nullable parameters have default
	if formats == nil {
		formats = strfmt.Default
	}

	cli := new(ZitiEdgeClient)
	cli.Transport = transport
	cli.Authentication = authentication.New(transport, formats)
	cli.CurrentAPISession = current_api_session.New(transport, formats)
	cli.CurrentIdentity = current_identity.New(transport, formats)
	cli.Enroll = enroll.New(transport, formats)
	cli.ExternalJWTSigner = external_jwt_signer.New(transport, formats)
	cli.Informational = informational.New(transport, formats)
	cli.PostureChecks = posture_checks.New(transport, formats)
	cli.Service = service.New(transport, formats)
	cli.Session = session.New(transport, formats)
	cli.WellKnown = well_known.New(transport, formats)
	return cli
}

// DefaultTransportConfig creates a TransportConfig with the
// default settings taken from the meta section of the spec file.
func DefaultTransportConfig() *TransportConfig {
	return &TransportConfig{
		Host:     DefaultHost,
		BasePath: DefaultBasePath,
		Schemes:  DefaultSchemes,
	}
}

// TransportConfig contains the transport related info,
// found in the meta section of the spec file.
type TransportConfig struct {
	Host     string
	BasePath string
	Schemes  []string
}

// WithHost overrides the default host,
// provided by the meta section of the spec file.
func (cfg *TransportConfig) WithHost(host string) *TransportConfig {
	cfg.Host = host
	return cfg
}

// WithBasePath overrides the default basePath,
// provided by the meta section of the spec file.
func (cfg *TransportConfig) WithBasePath(basePath string) *TransportConfig {
	cfg.BasePath = basePath
	return cfg
}

// WithSchemes overrides the default schemes,
// provided by the meta section of the spec file.
func (cfg *TransportConfig) WithSchemes(schemes []string) *TransportConfig {
	cfg.Schemes = schemes
	return cfg
}

// ZitiEdgeClient is a client for ziti edge client
type ZitiEdgeClient struct {
	Authentication authentication.ClientService

	CurrentAPISession current_api_session.ClientService

	CurrentIdentity current_identity.ClientService

	Enroll enroll.ClientService

	ExternalJWTSigner external_jwt_signer.ClientService

	Informational informational.ClientService

	PostureChecks posture_checks.ClientService

	Service service.ClientService

	Session session.ClientService

	WellKnown well_known.ClientService

	Transport runtime.ClientTransport
}

// SetTransport changes the transport on the client and all its subresources
func (c *ZitiEdgeClient) SetTransport(transport runtime.ClientTransport) {
	c.Transport = transport
	c.Authentication.SetTransport(transport)
	c.CurrentAPISession.SetTransport(transport)
	c.CurrentIdentity.SetTransport(transport)
	c.Enroll.SetTransport(transport)
	c.ExternalJWTSigner.SetTransport(transport)
	c.Informational.SetTransport(transport)
	c.PostureChecks.SetTransport(transport)
	c.Service.SetTransport(transport)
	c.Session.SetTransport(transport)
	c.WellKnown.SetTransport(transport)
}
