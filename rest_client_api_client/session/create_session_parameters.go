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

package session

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/openziti/edge/rest_model"
)

// NewCreateSessionParams creates a new CreateSessionParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateSessionParams() *CreateSessionParams {
	return &CreateSessionParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateSessionParamsWithTimeout creates a new CreateSessionParams object
// with the ability to set a timeout on a request.
func NewCreateSessionParamsWithTimeout(timeout time.Duration) *CreateSessionParams {
	return &CreateSessionParams{
		timeout: timeout,
	}
}

// NewCreateSessionParamsWithContext creates a new CreateSessionParams object
// with the ability to set a context for a request.
func NewCreateSessionParamsWithContext(ctx context.Context) *CreateSessionParams {
	return &CreateSessionParams{
		Context: ctx,
	}
}

// NewCreateSessionParamsWithHTTPClient creates a new CreateSessionParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateSessionParamsWithHTTPClient(client *http.Client) *CreateSessionParams {
	return &CreateSessionParams{
		HTTPClient: client,
	}
}

/* CreateSessionParams contains all the parameters to send to the API endpoint
   for the create session operation.

   Typically these are written to a http.Request.
*/
type CreateSessionParams struct {

	/* Session.

	   A session to create
	*/
	Session *rest_model.SessionCreate

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create session params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateSessionParams) WithDefaults() *CreateSessionParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create session params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateSessionParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create session params
func (o *CreateSessionParams) WithTimeout(timeout time.Duration) *CreateSessionParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create session params
func (o *CreateSessionParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create session params
func (o *CreateSessionParams) WithContext(ctx context.Context) *CreateSessionParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create session params
func (o *CreateSessionParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create session params
func (o *CreateSessionParams) WithHTTPClient(client *http.Client) *CreateSessionParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create session params
func (o *CreateSessionParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithSession adds the session to the create session params
func (o *CreateSessionParams) WithSession(session *rest_model.SessionCreate) *CreateSessionParams {
	o.SetSession(session)
	return o
}

// SetSession adds the session to the create session params
func (o *CreateSessionParams) SetSession(session *rest_model.SessionCreate) {
	o.Session = session
}

// WriteToRequest writes these params to a swagger request
func (o *CreateSessionParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Session != nil {
		if err := r.SetBodyParam(o.Session); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
