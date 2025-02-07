// Code generated by go-swagger; DO NOT EDIT.

//
// Copyright NetFoundry Inc.
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

package edge_router

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// ListEdgeRouterServiceEdgeRouterPoliciesReader is a Reader for the ListEdgeRouterServiceEdgeRouterPolicies structure.
type ListEdgeRouterServiceEdgeRouterPoliciesReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListEdgeRouterServiceEdgeRouterPoliciesReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListEdgeRouterServiceEdgeRouterPoliciesOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewListEdgeRouterServiceEdgeRouterPoliciesUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewListEdgeRouterServiceEdgeRouterPoliciesNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewListEdgeRouterServiceEdgeRouterPoliciesOK creates a ListEdgeRouterServiceEdgeRouterPoliciesOK with default headers values
func NewListEdgeRouterServiceEdgeRouterPoliciesOK() *ListEdgeRouterServiceEdgeRouterPoliciesOK {
	return &ListEdgeRouterServiceEdgeRouterPoliciesOK{}
}

/* ListEdgeRouterServiceEdgeRouterPoliciesOK describes a response with status code 200, with default header values.

A list of service policies
*/
type ListEdgeRouterServiceEdgeRouterPoliciesOK struct {
	Payload *rest_model.ListServicePoliciesEnvelope
}

func (o *ListEdgeRouterServiceEdgeRouterPoliciesOK) Error() string {
	return fmt.Sprintf("[GET /edge-routers/{id}/service-edge-router-policies][%d] listEdgeRouterServiceEdgeRouterPoliciesOK  %+v", 200, o.Payload)
}
func (o *ListEdgeRouterServiceEdgeRouterPoliciesOK) GetPayload() *rest_model.ListServicePoliciesEnvelope {
	return o.Payload
}

func (o *ListEdgeRouterServiceEdgeRouterPoliciesOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.ListServicePoliciesEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListEdgeRouterServiceEdgeRouterPoliciesUnauthorized creates a ListEdgeRouterServiceEdgeRouterPoliciesUnauthorized with default headers values
func NewListEdgeRouterServiceEdgeRouterPoliciesUnauthorized() *ListEdgeRouterServiceEdgeRouterPoliciesUnauthorized {
	return &ListEdgeRouterServiceEdgeRouterPoliciesUnauthorized{}
}

/* ListEdgeRouterServiceEdgeRouterPoliciesUnauthorized describes a response with status code 401, with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type ListEdgeRouterServiceEdgeRouterPoliciesUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *ListEdgeRouterServiceEdgeRouterPoliciesUnauthorized) Error() string {
	return fmt.Sprintf("[GET /edge-routers/{id}/service-edge-router-policies][%d] listEdgeRouterServiceEdgeRouterPoliciesUnauthorized  %+v", 401, o.Payload)
}
func (o *ListEdgeRouterServiceEdgeRouterPoliciesUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *ListEdgeRouterServiceEdgeRouterPoliciesUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewListEdgeRouterServiceEdgeRouterPoliciesNotFound creates a ListEdgeRouterServiceEdgeRouterPoliciesNotFound with default headers values
func NewListEdgeRouterServiceEdgeRouterPoliciesNotFound() *ListEdgeRouterServiceEdgeRouterPoliciesNotFound {
	return &ListEdgeRouterServiceEdgeRouterPoliciesNotFound{}
}

/* ListEdgeRouterServiceEdgeRouterPoliciesNotFound describes a response with status code 404, with default header values.

The requested resource does not exist
*/
type ListEdgeRouterServiceEdgeRouterPoliciesNotFound struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *ListEdgeRouterServiceEdgeRouterPoliciesNotFound) Error() string {
	return fmt.Sprintf("[GET /edge-routers/{id}/service-edge-router-policies][%d] listEdgeRouterServiceEdgeRouterPoliciesNotFound  %+v", 404, o.Payload)
}
func (o *ListEdgeRouterServiceEdgeRouterPoliciesNotFound) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *ListEdgeRouterServiceEdgeRouterPoliciesNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
