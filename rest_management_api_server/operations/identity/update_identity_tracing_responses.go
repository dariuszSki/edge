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

// UpdateIdentityTracingOKCode is the HTTP code returned for type UpdateIdentityTracingOK
const UpdateIdentityTracingOKCode int = 200

/*UpdateIdentityTracingOK Returns the document that represents the trace state

swagger:response updateIdentityTracingOK
*/
type UpdateIdentityTracingOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.TraceDetailEnvelope `json:"body,omitempty"`
}

// NewUpdateIdentityTracingOK creates UpdateIdentityTracingOK with default headers values
func NewUpdateIdentityTracingOK() *UpdateIdentityTracingOK {

	return &UpdateIdentityTracingOK{}
}

// WithPayload adds the payload to the update identity tracing o k response
func (o *UpdateIdentityTracingOK) WithPayload(payload *rest_model.TraceDetailEnvelope) *UpdateIdentityTracingOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the update identity tracing o k response
func (o *UpdateIdentityTracingOK) SetPayload(payload *rest_model.TraceDetailEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *UpdateIdentityTracingOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// UpdateIdentityTracingBadRequestCode is the HTTP code returned for type UpdateIdentityTracingBadRequest
const UpdateIdentityTracingBadRequestCode int = 400

/*UpdateIdentityTracingBadRequest The supplied request contains invalid fields or could not be parsed (json and non-json bodies). The error's code, message, and cause fields can be inspected for further information

swagger:response updateIdentityTracingBadRequest
*/
type UpdateIdentityTracingBadRequest struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewUpdateIdentityTracingBadRequest creates UpdateIdentityTracingBadRequest with default headers values
func NewUpdateIdentityTracingBadRequest() *UpdateIdentityTracingBadRequest {

	return &UpdateIdentityTracingBadRequest{}
}

// WithPayload adds the payload to the update identity tracing bad request response
func (o *UpdateIdentityTracingBadRequest) WithPayload(payload *rest_model.APIErrorEnvelope) *UpdateIdentityTracingBadRequest {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the update identity tracing bad request response
func (o *UpdateIdentityTracingBadRequest) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *UpdateIdentityTracingBadRequest) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(400)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// UpdateIdentityTracingUnauthorizedCode is the HTTP code returned for type UpdateIdentityTracingUnauthorized
const UpdateIdentityTracingUnauthorizedCode int = 401

/*UpdateIdentityTracingUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response updateIdentityTracingUnauthorized
*/
type UpdateIdentityTracingUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewUpdateIdentityTracingUnauthorized creates UpdateIdentityTracingUnauthorized with default headers values
func NewUpdateIdentityTracingUnauthorized() *UpdateIdentityTracingUnauthorized {

	return &UpdateIdentityTracingUnauthorized{}
}

// WithPayload adds the payload to the update identity tracing unauthorized response
func (o *UpdateIdentityTracingUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *UpdateIdentityTracingUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the update identity tracing unauthorized response
func (o *UpdateIdentityTracingUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *UpdateIdentityTracingUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// UpdateIdentityTracingNotFoundCode is the HTTP code returned for type UpdateIdentityTracingNotFound
const UpdateIdentityTracingNotFoundCode int = 404

/*UpdateIdentityTracingNotFound The requested resource does not exist

swagger:response updateIdentityTracingNotFound
*/
type UpdateIdentityTracingNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewUpdateIdentityTracingNotFound creates UpdateIdentityTracingNotFound with default headers values
func NewUpdateIdentityTracingNotFound() *UpdateIdentityTracingNotFound {

	return &UpdateIdentityTracingNotFound{}
}

// WithPayload adds the payload to the update identity tracing not found response
func (o *UpdateIdentityTracingNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *UpdateIdentityTracingNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the update identity tracing not found response
func (o *UpdateIdentityTracingNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *UpdateIdentityTracingNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
