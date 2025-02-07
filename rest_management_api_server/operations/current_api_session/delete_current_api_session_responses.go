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

package current_api_session

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// DeleteCurrentAPISessionOKCode is the HTTP code returned for type DeleteCurrentAPISessionOK
const DeleteCurrentAPISessionOKCode int = 200

/*DeleteCurrentAPISessionOK Base empty response

swagger:response deleteCurrentApiSessionOK
*/
type DeleteCurrentAPISessionOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.Empty `json:"body,omitempty"`
}

// NewDeleteCurrentAPISessionOK creates DeleteCurrentAPISessionOK with default headers values
func NewDeleteCurrentAPISessionOK() *DeleteCurrentAPISessionOK {

	return &DeleteCurrentAPISessionOK{}
}

// WithPayload adds the payload to the delete current Api session o k response
func (o *DeleteCurrentAPISessionOK) WithPayload(payload *rest_model.Empty) *DeleteCurrentAPISessionOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete current Api session o k response
func (o *DeleteCurrentAPISessionOK) SetPayload(payload *rest_model.Empty) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteCurrentAPISessionOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// DeleteCurrentAPISessionUnauthorizedCode is the HTTP code returned for type DeleteCurrentAPISessionUnauthorized
const DeleteCurrentAPISessionUnauthorizedCode int = 401

/*DeleteCurrentAPISessionUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response deleteCurrentApiSessionUnauthorized
*/
type DeleteCurrentAPISessionUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewDeleteCurrentAPISessionUnauthorized creates DeleteCurrentAPISessionUnauthorized with default headers values
func NewDeleteCurrentAPISessionUnauthorized() *DeleteCurrentAPISessionUnauthorized {

	return &DeleteCurrentAPISessionUnauthorized{}
}

// WithPayload adds the payload to the delete current Api session unauthorized response
func (o *DeleteCurrentAPISessionUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *DeleteCurrentAPISessionUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the delete current Api session unauthorized response
func (o *DeleteCurrentAPISessionUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *DeleteCurrentAPISessionUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
