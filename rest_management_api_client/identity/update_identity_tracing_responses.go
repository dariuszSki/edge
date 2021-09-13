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
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// UpdateIdentityTracingReader is a Reader for the UpdateIdentityTracing structure.
type UpdateIdentityTracingReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateIdentityTracingReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateIdentityTracingOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 400:
		result := NewUpdateIdentityTracingBadRequest()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 401:
		result := NewUpdateIdentityTracingUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewUpdateIdentityTracingNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewUpdateIdentityTracingOK creates a UpdateIdentityTracingOK with default headers values
func NewUpdateIdentityTracingOK() *UpdateIdentityTracingOK {
	return &UpdateIdentityTracingOK{}
}

/* UpdateIdentityTracingOK describes a response with status code 200, with default header values.

Returns the document that represents the trace state
*/
type UpdateIdentityTracingOK struct {
	Payload *rest_model.TraceDetailEnvelope
}

func (o *UpdateIdentityTracingOK) Error() string {
	return fmt.Sprintf("[PUT /identities/{id}/trace][%d] updateIdentityTracingOK  %+v", 200, o.Payload)
}
func (o *UpdateIdentityTracingOK) GetPayload() *rest_model.TraceDetailEnvelope {
	return o.Payload
}

func (o *UpdateIdentityTracingOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.TraceDetailEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateIdentityTracingBadRequest creates a UpdateIdentityTracingBadRequest with default headers values
func NewUpdateIdentityTracingBadRequest() *UpdateIdentityTracingBadRequest {
	return &UpdateIdentityTracingBadRequest{}
}

/* UpdateIdentityTracingBadRequest describes a response with status code 400, with default header values.

The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information
*/
type UpdateIdentityTracingBadRequest struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *UpdateIdentityTracingBadRequest) Error() string {
	return fmt.Sprintf("[PUT /identities/{id}/trace][%d] updateIdentityTracingBadRequest  %+v", 400, o.Payload)
}
func (o *UpdateIdentityTracingBadRequest) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *UpdateIdentityTracingBadRequest) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateIdentityTracingUnauthorized creates a UpdateIdentityTracingUnauthorized with default headers values
func NewUpdateIdentityTracingUnauthorized() *UpdateIdentityTracingUnauthorized {
	return &UpdateIdentityTracingUnauthorized{}
}

/* UpdateIdentityTracingUnauthorized describes a response with status code 401, with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type UpdateIdentityTracingUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *UpdateIdentityTracingUnauthorized) Error() string {
	return fmt.Sprintf("[PUT /identities/{id}/trace][%d] updateIdentityTracingUnauthorized  %+v", 401, o.Payload)
}
func (o *UpdateIdentityTracingUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *UpdateIdentityTracingUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewUpdateIdentityTracingNotFound creates a UpdateIdentityTracingNotFound with default headers values
func NewUpdateIdentityTracingNotFound() *UpdateIdentityTracingNotFound {
	return &UpdateIdentityTracingNotFound{}
}

/* UpdateIdentityTracingNotFound describes a response with status code 404, with default header values.

The requested resource does not exist
*/
type UpdateIdentityTracingNotFound struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *UpdateIdentityTracingNotFound) Error() string {
	return fmt.Sprintf("[PUT /identities/{id}/trace][%d] updateIdentityTracingNotFound  %+v", 404, o.Payload)
}
func (o *UpdateIdentityTracingNotFound) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *UpdateIdentityTracingNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
