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

package service_edge_router_policy

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"

	"github.com/openziti/edge/rest_model"
)

// ListServiceEdgeRouterPolicyEdgeRoutersOKCode is the HTTP code returned for type ListServiceEdgeRouterPolicyEdgeRoutersOK
const ListServiceEdgeRouterPolicyEdgeRoutersOKCode int = 200

/*ListServiceEdgeRouterPolicyEdgeRoutersOK A list of edge routers

swagger:response listServiceEdgeRouterPolicyEdgeRoutersOK
*/
type ListServiceEdgeRouterPolicyEdgeRoutersOK struct {

	/*
	  In: Body
	*/
	Payload *rest_model.ListEdgeRoutersEnvelope `json:"body,omitempty"`
}

// NewListServiceEdgeRouterPolicyEdgeRoutersOK creates ListServiceEdgeRouterPolicyEdgeRoutersOK with default headers values
func NewListServiceEdgeRouterPolicyEdgeRoutersOK() *ListServiceEdgeRouterPolicyEdgeRoutersOK {

	return &ListServiceEdgeRouterPolicyEdgeRoutersOK{}
}

// WithPayload adds the payload to the list service edge router policy edge routers o k response
func (o *ListServiceEdgeRouterPolicyEdgeRoutersOK) WithPayload(payload *rest_model.ListEdgeRoutersEnvelope) *ListServiceEdgeRouterPolicyEdgeRoutersOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list service edge router policy edge routers o k response
func (o *ListServiceEdgeRouterPolicyEdgeRoutersOK) SetPayload(payload *rest_model.ListEdgeRoutersEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListServiceEdgeRouterPolicyEdgeRoutersOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ListServiceEdgeRouterPolicyEdgeRoutersUnauthorizedCode is the HTTP code returned for type ListServiceEdgeRouterPolicyEdgeRoutersUnauthorized
const ListServiceEdgeRouterPolicyEdgeRoutersUnauthorizedCode int = 401

/*ListServiceEdgeRouterPolicyEdgeRoutersUnauthorized The currently supplied session does not have the correct access rights to request this resource

swagger:response listServiceEdgeRouterPolicyEdgeRoutersUnauthorized
*/
type ListServiceEdgeRouterPolicyEdgeRoutersUnauthorized struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewListServiceEdgeRouterPolicyEdgeRoutersUnauthorized creates ListServiceEdgeRouterPolicyEdgeRoutersUnauthorized with default headers values
func NewListServiceEdgeRouterPolicyEdgeRoutersUnauthorized() *ListServiceEdgeRouterPolicyEdgeRoutersUnauthorized {

	return &ListServiceEdgeRouterPolicyEdgeRoutersUnauthorized{}
}

// WithPayload adds the payload to the list service edge router policy edge routers unauthorized response
func (o *ListServiceEdgeRouterPolicyEdgeRoutersUnauthorized) WithPayload(payload *rest_model.APIErrorEnvelope) *ListServiceEdgeRouterPolicyEdgeRoutersUnauthorized {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list service edge router policy edge routers unauthorized response
func (o *ListServiceEdgeRouterPolicyEdgeRoutersUnauthorized) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListServiceEdgeRouterPolicyEdgeRoutersUnauthorized) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(401)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// ListServiceEdgeRouterPolicyEdgeRoutersNotFoundCode is the HTTP code returned for type ListServiceEdgeRouterPolicyEdgeRoutersNotFound
const ListServiceEdgeRouterPolicyEdgeRoutersNotFoundCode int = 404

/*ListServiceEdgeRouterPolicyEdgeRoutersNotFound The requested resource does not exist

swagger:response listServiceEdgeRouterPolicyEdgeRoutersNotFound
*/
type ListServiceEdgeRouterPolicyEdgeRoutersNotFound struct {

	/*
	  In: Body
	*/
	Payload *rest_model.APIErrorEnvelope `json:"body,omitempty"`
}

// NewListServiceEdgeRouterPolicyEdgeRoutersNotFound creates ListServiceEdgeRouterPolicyEdgeRoutersNotFound with default headers values
func NewListServiceEdgeRouterPolicyEdgeRoutersNotFound() *ListServiceEdgeRouterPolicyEdgeRoutersNotFound {

	return &ListServiceEdgeRouterPolicyEdgeRoutersNotFound{}
}

// WithPayload adds the payload to the list service edge router policy edge routers not found response
func (o *ListServiceEdgeRouterPolicyEdgeRoutersNotFound) WithPayload(payload *rest_model.APIErrorEnvelope) *ListServiceEdgeRouterPolicyEdgeRoutersNotFound {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the list service edge router policy edge routers not found response
func (o *ListServiceEdgeRouterPolicyEdgeRoutersNotFound) SetPayload(payload *rest_model.APIErrorEnvelope) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *ListServiceEdgeRouterPolicyEdgeRoutersNotFound) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(404)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}
