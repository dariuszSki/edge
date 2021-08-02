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
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// ListIdentityTypesOKCode is the HTTP code returned for type ListIdentityTypesOK
const ListIdentityTypesOKCode int = 200

/*ListIdentityTypesOK A list of identity types

swagger:response listIdentityTypesOK
*/
type ListIdentityTypesOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.ListIdentityTypesEnvelope `json:"body,omitempty"`
}

// NewListIdentityTypesOK creates ListIdentityTypesOK with default headers values
func NewListIdentityTypesOK() *ListIdentityTypesOK {

	return &ListIdentityTypesOK{}
}

// WithPayload adds the payload to the list identity types o k response
func (o *ListIdentityTypesOK) WithPayload(payload *rest_model.ListIdentityTypesEnvelope) *ListIdentityTypesOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list identity types o k response
func (o *ListIdentityTypesOK) SetPayload(payload *rest_model.ListIdentityTypesEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListIdentityTypesOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ListIdentityTypesBadRequestCode is the HTTP code returned for type ListIdentityTypesBadRequest
const ListIdentityTypesBadRequestCode int = 400

/*ListIdentityTypesBadRequest The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information

swagger:response listIdentityTypesBadRequest
*/
type ListIdentityTypesBadRequest struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewListIdentityTypesBadRequest creates ListIdentityTypesBadRequest with default headers values
func NewListIdentityTypesBadRequest() *ListIdentityTypesBadRequest {

	return &ListIdentityTypesBadRequest{}
}

// WithPayload adds the payload to the list identity types bad request response
func (o *ListIdentityTypesBadRequest) WithPayload(payload *rest_model.APIErrorEnvelope) *ListIdentityTypesBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list identity types bad request response
func (o *ListIdentityTypesBadRequest) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListIdentityTypesBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ListIdentityTypesUnauthorizedCode is the HTTP code returned for type ListIdentityTypesUnauthorized
const ListIdentityTypesUnauthorizedCode int = 401

/*ListIdentityTypesUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response listIdentityTypesUnauthorized
*/
type ListIdentityTypesUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewListIdentityTypesUnauthorized creates ListIdentityTypesUnauthorized with default headers values
func NewListIdentityTypesUnauthorized() *ListIdentityTypesUnauthorized {

	return &ListIdentityTypesUnauthorized{}
}

// WithPayload adds the payload to the list identity types unauthorized response
func (o *ListIdentityTypesUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *ListIdentityTypesUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list identity types unauthorized response
func (o *ListIdentityTypesUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListIdentityTypesUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
