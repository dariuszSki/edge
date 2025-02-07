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

package api_session

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// DetailAPISessionsReader is a Reader for the DetailAPISessions structure.
type DetailAPISessionsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DetailAPISessionsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDetailAPISessionsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 401:
		result := NewDetailAPISessionsUnauthorized()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	case 404:
		result := NewDetailAPISessionsNotFound()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDetailAPISessionsOK creates a DetailAPISessionsOK with default headers values
func NewDetailAPISessionsOK() *DetailAPISessionsOK {
	return &DetailAPISessionsOK{}
}

/* DetailAPISessionsOK describes a response with status code 200, with default header values.

Retrieves a singular API Session by id
*/
type DetailAPISessionsOK struct {
	Payload *rest_model.DetailAPISessionEnvelope
}

func (o *DetailAPISessionsOK) Error() string {
	return fmt.Sprintf("[GET /api-sessions/{id}][%d] detailApiSessionsOK  %+v", 200, o.Payload)
}
func (o *DetailAPISessionsOK) GetPayload() *rest_model.DetailAPISessionEnvelope {
	return o.Payload
}

func (o *DetailAPISessionsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.DetailAPISessionEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDetailAPISessionsUnauthorized creates a DetailAPISessionsUnauthorized with default headers values
func NewDetailAPISessionsUnauthorized() *DetailAPISessionsUnauthorized {
	return &DetailAPISessionsUnauthorized{}
}

/* DetailAPISessionsUnauthorized describes a response with status code 401, with default header values.

The currently supplied session does not have the correct access rights to request this resource
*/
type DetailAPISessionsUnauthorized struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DetailAPISessionsUnauthorized) Error() string {
	return fmt.Sprintf("[GET /api-sessions/{id}][%d] detailApiSessionsUnauthorized  %+v", 401, o.Payload)
}
func (o *DetailAPISessionsUnauthorized) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DetailAPISessionsUnauthorized) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewDetailAPISessionsNotFound creates a DetailAPISessionsNotFound with default headers values
func NewDetailAPISessionsNotFound() *DetailAPISessionsNotFound {
	return &DetailAPISessionsNotFound{}
}

/* DetailAPISessionsNotFound describes a response with status code 404, with default header values.

The requested resource does not exist
*/
type DetailAPISessionsNotFound struct {
	Payload *rest_model.APIErrorEnvelope
}

func (o *DetailAPISessionsNotFound) Error() string {
	return fmt.Sprintf("[GET /api-sessions/{id}][%d] detailApiSessionsNotFound  %+v", 404, o.Payload)
}
func (o *DetailAPISessionsNotFound) GetPayload() *rest_model.APIErrorEnvelope {
	return o.Payload
}

func (o *DetailAPISessionsNotFound) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(rest_model.APIErrorEnvelope)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
