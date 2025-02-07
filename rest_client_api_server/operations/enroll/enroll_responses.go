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

package enroll

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// EnrollOKCode is the HTTP code returned for type EnrollOK
const EnrollOKCode int = 200

/*EnrollOK Base empty response

swagger:response enrollOK
*/
type EnrollOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.Empty `json:"body,omitempty"`
}

// NewEnrollOK creates EnrollOK with default headers values
func NewEnrollOK() *EnrollOK {

	return &EnrollOK{}
}

// WithPayload adds the payload to the enroll o k response
func (o *EnrollOK) WithPayload(payload *rest_model.Empty) *EnrollOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the enroll o k response
func (o *EnrollOK) SetPayload(payload *rest_model.Empty) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *EnrollOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// EnrollNotFoundCode is the HTTP code returned for type EnrollNotFound
const EnrollNotFoundCode int = 404

/*EnrollNotFound The requested resource does not exist

swagger:response enrollNotFound
*/
type EnrollNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewEnrollNotFound creates EnrollNotFound with default headers values
func NewEnrollNotFound() *EnrollNotFound {

	return &EnrollNotFound{}
}

// WithPayload adds the payload to the enroll not found response
func (o *EnrollNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *EnrollNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the enroll not found response
func (o *EnrollNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *EnrollNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
