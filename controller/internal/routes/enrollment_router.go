/*
	Copyright NetFoundry, Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package routes

import (
	"github.com/go-openapi/runtime/middleware"
	"github.com/openziti/edge/controller/env"
	"github.com/openziti/edge/controller/internal/permissions"
	"github.com/openziti/edge/controller/response"
	"github.com/openziti/edge/rest_management_api_server/operations/enrollment"
)

func init() {
	r := NewEnrollmentRouter()
	env.AddRouter(r)
}

type EnrollmentRouter struct {
	BasePath string
}

func NewEnrollmentRouter() *EnrollmentRouter {
	return &EnrollmentRouter{
		BasePath: "/" + EntityNameEnrollment,
	}
}

func (r *EnrollmentRouter) Register(ae *env.AppEnv) {

	ae.ManagementApi.EnrollmentDeleteEnrollmentHandler = enrollment.DeleteEnrollmentHandlerFunc(func(params enrollment.DeleteEnrollmentParams, _ interface{}) middleware.Responder {
		return ae.IsAllowed(r.Delete, params.HTTPRequest, params.ID, "", permissions.IsAdmin())
	})

	ae.ManagementApi.EnrollmentDetailEnrollmentHandler = enrollment.DetailEnrollmentHandlerFunc(func(params enrollment.DetailEnrollmentParams, _ interface{}) middleware.Responder {
		return ae.IsAllowed(r.Detail, params.HTTPRequest, params.ID, "", permissions.IsAdmin())
	})

	ae.ManagementApi.EnrollmentListEnrollmentsHandler = enrollment.ListEnrollmentsHandlerFunc(func(params enrollment.ListEnrollmentsParams, _ interface{}) middleware.Responder {
		return ae.IsAllowed(r.List, params.HTTPRequest, "", "", permissions.IsAdmin())
	})
}

func (r *EnrollmentRouter) List(ae *env.AppEnv, rc *response.RequestContext) {
	ListWithHandler(ae, rc, ae.Handlers.Enrollment, MapEnrollmentToRestEntity)
}

func (r *EnrollmentRouter) Detail(ae *env.AppEnv, rc *response.RequestContext) {
	DetailWithHandler(ae, rc, ae.Handlers.Enrollment, MapEnrollmentToRestEntity)
}

func (r *EnrollmentRouter) Delete(ae *env.AppEnv, rc *response.RequestContext) {
	DeleteWithHandler(rc, ae.Handlers.Enrollment)
}
