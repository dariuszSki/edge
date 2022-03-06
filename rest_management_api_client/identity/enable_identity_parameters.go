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
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewEnableIdentityParams creates a new EnableIdentityParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewEnableIdentityParams() *EnableIdentityParams {
	return &EnableIdentityParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewEnableIdentityParamsWithTimeout creates a new EnableIdentityParams object
// with the ability to set a timeout on a request.
func NewEnableIdentityParamsWithTimeout(timeout time.Duration) *EnableIdentityParams {
	return &EnableIdentityParams{
		timeout: timeout,
	}
}

// NewEnableIdentityParamsWithContext creates a new EnableIdentityParams object
// with the ability to set a context for a request.
func NewEnableIdentityParamsWithContext(ctx context.Context) *EnableIdentityParams {
	return &EnableIdentityParams{
		Context: ctx,
	}
}

// NewEnableIdentityParamsWithHTTPClient creates a new EnableIdentityParams object
// with the ability to set a custom HTTPClient for a request.
func NewEnableIdentityParamsWithHTTPClient(client *http.Client) *EnableIdentityParams {
	return &EnableIdentityParams{
		HTTPClient: client,
	}
}

/* EnableIdentityParams contains all the parameters to send to the API endpoint
   for the enable identity operation.

   Typically these are written to a http.Request.
*/
type EnableIdentityParams struct {

	/* ID.

	   The id of the requested resource
	*/
	ID string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the enable identity params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *EnableIdentityParams) WithDefaults() *EnableIdentityParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the enable identity params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *EnableIdentityParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the enable identity params
func (o *EnableIdentityParams) WithTimeout(timeout time.Duration) *EnableIdentityParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the enable identity params
func (o *EnableIdentityParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the enable identity params
func (o *EnableIdentityParams) WithContext(ctx context.Context) *EnableIdentityParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the enable identity params
func (o *EnableIdentityParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the enable identity params
func (o *EnableIdentityParams) WithHTTPClient(client *http.Client) *EnableIdentityParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the enable identity params
func (o *EnableIdentityParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithID adds the id to the enable identity params
func (o *EnableIdentityParams) WithID(id string) *EnableIdentityParams {
	o.SetID(id)
	return o
}

// SetID adds the id to the enable identity params
func (o *EnableIdentityParams) SetID(id string) {
	o.ID = id
}

// WriteToRequest writes these params to a swagger request
func (o *EnableIdentityParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// path param id
	if err := r.SetPathParam("id", o.ID); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
