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

package identity

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new identity API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for identity API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	AssociateIdentitysServiceConfigs(params *AssociateIdentitysServiceConfigsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*AssociateIdentitysServiceConfigsOK, error)

	CreateIdentity(params *CreateIdentityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateIdentityCreated, error)

	DeleteIdentity(params *DeleteIdentityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteIdentityOK, error)

	DetailIdentity(params *DetailIdentityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DetailIdentityOK, error)

	DetailIdentityType(params *DetailIdentityTypeParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DetailIdentityTypeOK, error)

	DisassociateIdentitysServiceConfigs(params *DisassociateIdentitysServiceConfigsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DisassociateIdentitysServiceConfigsOK, error)

	GetIdentityAuthenticators(params *GetIdentityAuthenticatorsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetIdentityAuthenticatorsOK, error)

	GetIdentityFailedServiceRequests(params *GetIdentityFailedServiceRequestsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetIdentityFailedServiceRequestsOK, error)

	GetIdentityPolicyAdvice(params *GetIdentityPolicyAdviceParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetIdentityPolicyAdviceOK, error)

	GetIdentityPostureData(params *GetIdentityPostureDataParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetIdentityPostureDataOK, error)

	ListIdentities(params *ListIdentitiesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListIdentitiesOK, error)

	ListIdentityEdgeRouters(params *ListIdentityEdgeRoutersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListIdentityEdgeRoutersOK, error)

	ListIdentityServicePolicies(params *ListIdentityServicePoliciesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListIdentityServicePoliciesOK, error)

	ListIdentityServices(params *ListIdentityServicesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListIdentityServicesOK, error)

	ListIdentityTypes(params *ListIdentityTypesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListIdentityTypesOK, error)

	ListIdentitysEdgeRouterPolicies(params *ListIdentitysEdgeRouterPoliciesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListIdentitysEdgeRouterPoliciesOK, error)

	ListIdentitysServiceConfigs(params *ListIdentitysServiceConfigsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListIdentitysServiceConfigsOK, error)

	PatchIdentity(params *PatchIdentityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PatchIdentityOK, error)

	RemoveIdentityMfa(params *RemoveIdentityMfaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RemoveIdentityMfaOK, error)

	UpdateIdentity(params *UpdateIdentityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateIdentityOK, error)

	UpdateIdentityTracing(params *UpdateIdentityTracingParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateIdentityTracingOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  AssociateIdentitysServiceConfigs associates service configs for a specific identity

  Associate service configs to a specific identity
*/
func (a *Client) AssociateIdentitysServiceConfigs(params *AssociateIdentitysServiceConfigsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*AssociateIdentitysServiceConfigsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAssociateIdentitysServiceConfigsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "associateIdentitysServiceConfigs",
		Method:             "POST",
		PathPattern:        "/identities/{id}/service-configs",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &AssociateIdentitysServiceConfigsReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*AssociateIdentitysServiceConfigsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for associateIdentitysServiceConfigs: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  CreateIdentity creates an identity resource

  Create an identity resource. Requires admin access.
*/
func (a *Client) CreateIdentity(params *CreateIdentityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateIdentityCreated, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateIdentityParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "createIdentity",
		Method:             "POST",
		PathPattern:        "/identities",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateIdentityReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*CreateIdentityCreated)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for createIdentity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DeleteIdentity deletes an identity

  Delete an identity by id. Requires admin access.
*/
func (a *Client) DeleteIdentity(params *DeleteIdentityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteIdentityOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteIdentityParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "deleteIdentity",
		Method:             "DELETE",
		PathPattern:        "/identities/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteIdentityReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*DeleteIdentityOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for deleteIdentity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DetailIdentity retrieves a single identity

  Retrieves a single identity by id. Requires admin access.
*/
func (a *Client) DetailIdentity(params *DetailIdentityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DetailIdentityOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDetailIdentityParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "detailIdentity",
		Method:             "GET",
		PathPattern:        "/identities/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DetailIdentityReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*DetailIdentityOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for detailIdentity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DetailIdentityType retrieves a identity type

  Retrieves a single identity type by id. Requires admin access.
*/
func (a *Client) DetailIdentityType(params *DetailIdentityTypeParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DetailIdentityTypeOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDetailIdentityTypeParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "detailIdentityType",
		Method:             "GET",
		PathPattern:        "/identity-types/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DetailIdentityTypeReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*DetailIdentityTypeOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for detailIdentityType: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  DisassociateIdentitysServiceConfigs removes associated service configs from a specific identity

  Remove service configs from a specific identity
*/
func (a *Client) DisassociateIdentitysServiceConfigs(params *DisassociateIdentitysServiceConfigsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DisassociateIdentitysServiceConfigsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDisassociateIdentitysServiceConfigsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "disassociateIdentitysServiceConfigs",
		Method:             "DELETE",
		PathPattern:        "/identities/{id}/service-configs",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DisassociateIdentitysServiceConfigsReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*DisassociateIdentitysServiceConfigsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for disassociateIdentitysServiceConfigs: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetIdentityAuthenticators retrieves the curent authenticators of a specific identity

  Returns a list of authenticators associated to the idetity specified

*/
func (a *Client) GetIdentityAuthenticators(params *GetIdentityAuthenticatorsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetIdentityAuthenticatorsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetIdentityAuthenticatorsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getIdentityAuthenticators",
		Method:             "GET",
		PathPattern:        "/identities/{id}/authenticators",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetIdentityAuthenticatorsReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetIdentityAuthenticatorsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getIdentityAuthenticators: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetIdentityFailedServiceRequests retrieves a list of the most recent service failure requests due to posture checks

  Returns a list of service session requests that failed due to posture checks. The entries will contain
every policy that was verified against and every failed check in each policy. Each check will include
the historical posture data and posture check configuration.

*/
func (a *Client) GetIdentityFailedServiceRequests(params *GetIdentityFailedServiceRequestsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetIdentityFailedServiceRequestsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetIdentityFailedServiceRequestsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getIdentityFailedServiceRequests",
		Method:             "GET",
		PathPattern:        "/identities/{id}/failed-service-requests",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetIdentityFailedServiceRequestsReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetIdentityFailedServiceRequestsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getIdentityFailedServiceRequests: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetIdentityPolicyAdvice analyzes policies relating the given identity and service

  Analyzes policies to see if the given identity should be able to dial or bind the given service. |
Will check services policies to see if the identity can access the service. Will check edge router policies |
to check if the identity and service have access to common edge routers so that a connnection can be made. |
Will also check if at least one edge router is on-line. Requires admin access.

*/
func (a *Client) GetIdentityPolicyAdvice(params *GetIdentityPolicyAdviceParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetIdentityPolicyAdviceOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetIdentityPolicyAdviceParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getIdentityPolicyAdvice",
		Method:             "GET",
		PathPattern:        "/identities/{id}/policy-advice/{serviceId}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetIdentityPolicyAdviceReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetIdentityPolicyAdviceOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getIdentityPolicyAdvice: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  GetIdentityPostureData retrieves the curent posture data for a specific identity

  Returns a nested map data represeting the posture data of the identity.
This data should be considered volatile.

*/
func (a *Client) GetIdentityPostureData(params *GetIdentityPostureDataParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetIdentityPostureDataOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetIdentityPostureDataParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "getIdentityPostureData",
		Method:             "GET",
		PathPattern:        "/identities/{id}/posture-data",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetIdentityPostureDataReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*GetIdentityPostureDataOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for getIdentityPostureData: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListIdentities lists identities

  Retrieves a list of identity resources; supports filtering, sorting, and pagination. Requires admin access.

*/
func (a *Client) ListIdentities(params *ListIdentitiesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListIdentitiesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListIdentitiesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listIdentities",
		Method:             "GET",
		PathPattern:        "/identities",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListIdentitiesReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ListIdentitiesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listIdentities: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListIdentityEdgeRouters lists accessible edge routers

  Retrieves a list of edge-routers that the given identity may use to access services. Supports filtering, sorting, and pagination. Requires admin access.

*/
func (a *Client) ListIdentityEdgeRouters(params *ListIdentityEdgeRoutersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListIdentityEdgeRoutersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListIdentityEdgeRoutersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listIdentityEdgeRouters",
		Method:             "GET",
		PathPattern:        "/identities/{id}/edge-routers",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListIdentityEdgeRoutersReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ListIdentityEdgeRoutersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listIdentityEdgeRouters: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListIdentityServicePolicies lists the service policies that affect an identity

  Retrieves a list of service policies that apply to the specified identity.
*/
func (a *Client) ListIdentityServicePolicies(params *ListIdentityServicePoliciesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListIdentityServicePoliciesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListIdentityServicePoliciesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listIdentityServicePolicies",
		Method:             "GET",
		PathPattern:        "/identities/{id}/service-policies",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListIdentityServicePoliciesReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ListIdentityServicePoliciesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listIdentityServicePolicies: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListIdentityServices lists accessible services

  Retrieves a list of services that the given identity has access to. Supports filtering, sorting, and pagination. Requires admin access.

*/
func (a *Client) ListIdentityServices(params *ListIdentityServicesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListIdentityServicesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListIdentityServicesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listIdentityServices",
		Method:             "GET",
		PathPattern:        "/identities/{id}/services",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListIdentityServicesReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ListIdentityServicesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listIdentityServices: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListIdentityTypes lists available identity types

  Retrieves a list of identity types; supports filtering, sorting, and pagination. Requires admin access.

*/
func (a *Client) ListIdentityTypes(params *ListIdentityTypesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListIdentityTypesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListIdentityTypesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listIdentityTypes",
		Method:             "GET",
		PathPattern:        "/identity-types",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListIdentityTypesReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ListIdentityTypesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listIdentityTypes: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListIdentitysEdgeRouterPolicies lists the edge router policies that affect an identity

  Retrieves a list of edge router policies that apply to the specified identity.
*/
func (a *Client) ListIdentitysEdgeRouterPolicies(params *ListIdentitysEdgeRouterPoliciesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListIdentitysEdgeRouterPoliciesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListIdentitysEdgeRouterPoliciesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listIdentitysEdgeRouterPolicies",
		Method:             "GET",
		PathPattern:        "/identities/{id}/edge-router-policies",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListIdentitysEdgeRouterPoliciesReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ListIdentitysEdgeRouterPoliciesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listIdentitysEdgeRouterPolicies: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  ListIdentitysServiceConfigs lists the service configs associated a specific identity

  Retrieves a list of service configs associated to a specific identity
*/
func (a *Client) ListIdentitysServiceConfigs(params *ListIdentitysServiceConfigsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ListIdentitysServiceConfigsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewListIdentitysServiceConfigsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "listIdentitysServiceConfigs",
		Method:             "GET",
		PathPattern:        "/identities/{id}/service-configs",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ListIdentitysServiceConfigsReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*ListIdentitysServiceConfigsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for listIdentitysServiceConfigs: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  PatchIdentity updates the supplied fields on an identity

  Update the supplied fields on an identity. Requires admin access.
*/
func (a *Client) PatchIdentity(params *PatchIdentityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PatchIdentityOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPatchIdentityParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "patchIdentity",
		Method:             "PATCH",
		PathPattern:        "/identities/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PatchIdentityReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*PatchIdentityOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for patchIdentity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  RemoveIdentityMfa removes m f a from an identitity

  Allows an admin to remove MFA enrollment from a specific identity. Requires admin.

*/
func (a *Client) RemoveIdentityMfa(params *RemoveIdentityMfaParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RemoveIdentityMfaOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRemoveIdentityMfaParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "removeIdentityMfa",
		Method:             "DELETE",
		PathPattern:        "/identities/{id}/mfa",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RemoveIdentityMfaReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*RemoveIdentityMfaOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for removeIdentityMfa: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  UpdateIdentity updates all fields on an identity

  Update all fields on an identity by id. Requires admin access.
*/
func (a *Client) UpdateIdentity(params *UpdateIdentityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateIdentityOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateIdentityParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateIdentity",
		Method:             "PUT",
		PathPattern:        "/identities/{id}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateIdentityReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*UpdateIdentityOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateIdentity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  UpdateIdentityTracing enables disable data flow tracing for an identity

  Allows an admin to enable/disable data flow tracing for an identity

*/
func (a *Client) UpdateIdentityTracing(params *UpdateIdentityTracingParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateIdentityTracingOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateIdentityTracingParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "updateIdentityTracing",
		Method:             "PUT",
		PathPattern:        "/identities/{id}/trace",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateIdentityTracingReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*UpdateIdentityTracingOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for updateIdentityTracing: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
