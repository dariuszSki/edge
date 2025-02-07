/*
	Copyright NetFoundry Inc.

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
	"fmt"
	"github.com/michaelquigley/pfxlog"
	"github.com/openziti/edge/controller/env"
	"github.com/openziti/edge/controller/model"
	"github.com/openziti/edge/controller/response"
	"github.com/openziti/edge/rest_model"
	"github.com/openziti/fabric/controller/models"
)

const EntityNameIdentityType = "identity-types"

var IdentityTypeLinkFactory = NewBasicLinkFactory(EntityNameIdentityType)

func MapIdentityTypeToRestEntity(_ *env.AppEnv, _ *response.RequestContext, identityTypeModel models.Entity) (interface{}, error) {
	identityType, ok := identityTypeModel.(*model.IdentityType)

	if !ok {
		err := fmt.Errorf("entity is not an identity type \"%s\"", identityTypeModel.GetId())
		log := pfxlog.Logger()
		log.Error(err)
		return nil, err
	}

	restModel := MapIdentityTypeToRestModel(identityType)

	return restModel, nil
}

func MapIdentityTypeToRestModel(identityType *model.IdentityType) *rest_model.IdentityTypeDetail {
	ret := &rest_model.IdentityTypeDetail{
		BaseEntity: BaseEntityToRestModel(identityType, IdentityLinkFactory),
		Name:       identityType.Name,
	}
	return ret
}
