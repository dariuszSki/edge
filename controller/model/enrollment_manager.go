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

package model

import (
	"fmt"
	"github.com/openziti/edge/controller/apierror"
	"github.com/openziti/edge/controller/persistence"
	"github.com/openziti/edge/pb/edge_cmd_pb"
	"github.com/openziti/fabric/controller/command"
	"github.com/openziti/fabric/controller/fields"
	"github.com/openziti/fabric/controller/models"
	"github.com/openziti/fabric/controller/network"
	"github.com/openziti/fabric/pb/cmd_pb"
	"github.com/openziti/foundation/v2/errorz"
	"github.com/openziti/storage/boltz"
	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
	"time"
)

type EnrollmentManager struct {
	baseEntityManager
	enrollmentStore persistence.EnrollmentStore
}

func NewEnrollmentManager(env Env) *EnrollmentManager {
	manager := &EnrollmentManager{
		baseEntityManager: newBaseEntityManager(env, env.GetStores().Enrollment),
		enrollmentStore:   env.GetStores().Enrollment,
	}

	manager.impl = manager

	network.RegisterManagerDecoder[*Enrollment](env.GetHostController().GetNetwork().GetManagers(), manager)
	RegisterCommand(env, &ReplaceEnrollmentWithAuthenticatorCmd{}, &edge_cmd_pb.ReplaceEnrollmentWithAuthenticatorCmd{})

	return manager
}

func (self *EnrollmentManager) Create(entity *Enrollment) error {
	return network.DispatchCreate[*Enrollment](self, entity)
}

func (self *EnrollmentManager) ApplyCreate(cmd *command.CreateEntityCommand[*Enrollment]) error {
	model := cmd.Entity

	if model.IdentityId == nil {
		return apierror.NewBadRequestFieldError(*errorz.NewFieldError("identity not found", "identityId", model.IdentityId))
	}

	identity, err := self.env.GetManagers().Identity.Read(*model.IdentityId)

	if err != nil || identity == nil {
		return apierror.NewBadRequestFieldError(*errorz.NewFieldError("identity not found", "identityId", model.IdentityId))
	}

	if model.ExpiresAt.Before(time.Now()) {
		return apierror.NewBadRequestFieldError(*errorz.NewFieldError("expiresAt must be in the future", "expiresAt", model.ExpiresAt))
	}

	expiresAt := model.ExpiresAt.UTC()
	model.ExpiresAt = &expiresAt

	switch model.Method {
	case persistence.MethodEnrollOttCa:
		if model.CaId == nil {
			return apierror.NewBadRequestFieldError(*errorz.NewFieldError("ca not found", "caId", model.CaId))
		}

		ca, err := self.env.GetManagers().Ca.Read(*model.CaId)

		if err != nil || ca == nil {
			return apierror.NewBadRequestFieldError(*errorz.NewFieldError("ca not found", "caId", model.CaId))
		}
	case persistence.MethodAuthenticatorUpdb:
		if model.Username == nil || *model.Username == "" {
			return apierror.NewBadRequestFieldError(*errorz.NewFieldError("username not provided", "username", model.Username))
		}
	case persistence.MethodEnrollOtt:
	default:
		return apierror.NewBadRequestFieldError(*errorz.NewFieldError("unsupported enrollment method", "method", model.Method))
	}

	enrollments, err := self.Query(fmt.Sprintf(`identity="%s"`, identity.Id))

	if err != nil {
		return err
	}

	for _, enrollment := range enrollments {
		if enrollment.Method == model.Method {
			return apierror.NewEnrollmentExists(model.Method)
		}
	}

	if err := model.FillJwtInfoWithExpiresAt(self.env, identity.Id, *model.ExpiresAt); err != nil {
		return err
	}

	_, err = self.createEntity(model)
	return err
}

func (self *EnrollmentManager) Update(entity *Enrollment, checker fields.UpdatedFields) error {
	return network.DispatchUpdate[*Enrollment](self, entity, checker)
}

func (self *EnrollmentManager) ApplyUpdate(cmd *command.UpdateEntityCommand[*Enrollment]) error {
	return self.updateEntity(cmd.Entity, cmd.UpdatedFields)
}

func (self *EnrollmentManager) newModelEntity() edgeEntity {
	return &Enrollment{}
}

func (self *EnrollmentManager) getEnrollmentMethod(ctx EnrollmentContext) (string, error) {
	method := ctx.GetMethod()

	if method == persistence.MethodEnrollCa {
		return method, nil
	}

	token := ctx.GetToken()

	// token present, assumes all other enrollment methods
	enrollment, err := self.ReadByToken(token)

	if err != nil {
		return "", err
	}

	if enrollment == nil {
		return "", apierror.NewInvalidEnrollmentToken()
	}

	method = enrollment.Method

	return method, nil
}

func (self *EnrollmentManager) Enroll(ctx EnrollmentContext) (*EnrollmentResult, error) {
	method, err := self.getEnrollmentMethod(ctx)

	if err != nil {
		return nil, err
	}

	enrollModule := self.env.GetEnrollRegistry().GetByMethod(method)

	if enrollModule == nil {
		return nil, apierror.NewInvalidEnrollMethod()
	}

	return enrollModule.Process(ctx)
}

func (self *EnrollmentManager) ReadByToken(token string) (*Enrollment, error) {
	enrollment := &Enrollment{}

	err := self.env.GetDbProvider().GetDb().View(func(tx *bbolt.Tx) error {
		boltEntity, err := self.env.GetStores().Enrollment.LoadOneByToken(tx, token)

		if err != nil {
			return err
		}

		if boltEntity == nil {
			enrollment = nil
			return nil
		}

		return enrollment.fillFrom(self, tx, boltEntity)
	})

	if err != nil {
		return nil, err
	}

	return enrollment, nil
}

func (self *EnrollmentManager) ReplaceWithAuthenticator(enrollmentId string, authenticator *Authenticator) error {
	return self.Dispatch(&ReplaceEnrollmentWithAuthenticatorCmd{
		manager:       self,
		enrollmentId:  enrollmentId,
		authenticator: authenticator,
	})
}

func (self *EnrollmentManager) ApplyReplaceEncoderWithAuthenticatorCommand(cmd *ReplaceEnrollmentWithAuthenticatorCmd) error {
	return self.env.GetDbProvider().GetDb().Update(func(tx *bbolt.Tx) error {
		ctx := boltz.NewMutateContext(tx)

		err := self.env.GetStores().Enrollment.DeleteById(ctx, cmd.enrollmentId)
		if err != nil {
			return err
		}

		_, err = self.env.GetManagers().Authenticator.createEntityInTx(ctx, cmd.authenticator)
		return err
	})
}

func (self *EnrollmentManager) readInTx(tx *bbolt.Tx, id string) (*Enrollment, error) {
	modelEntity := &Enrollment{}
	if err := self.readEntityInTx(tx, id, modelEntity); err != nil {
		return nil, err
	}
	return modelEntity, nil
}

func (self *EnrollmentManager) Read(id string) (*Enrollment, error) {
	entity := &Enrollment{}
	if err := self.readEntity(id, entity); err != nil {
		return nil, err
	}
	return entity, nil
}

func (self *EnrollmentManager) RefreshJwt(id string, expiresAt time.Time) error {
	enrollment, err := self.Read(id)

	if err != nil {
		if boltz.IsErrNotFoundErr(err) {
			return errorz.NewNotFound()
		}

		return err
	}

	if enrollment.Jwt == "" {
		return apierror.NewInvalidEnrollMethod()
	}

	if expiresAt.Before(time.Now()) {
		return errorz.NewFieldError("must be after the current date and time", "expiresAt", expiresAt)
	}

	if err := enrollment.FillJwtInfoWithExpiresAt(self.env, *enrollment.IdentityId, expiresAt); err != nil {
		return err
	}

	err = self.Update(enrollment, fields.UpdatedFieldsMap{
		persistence.FieldEnrollmentJwt:       struct{}{},
		persistence.FieldEnrollmentExpiresAt: struct{}{},
		persistence.FieldEnrollmentIssuedAt:  struct{}{},
	})

	return err
}

func (self *EnrollmentManager) Query(query string) ([]*Enrollment, error) {
	var enrollments []*Enrollment
	if err := self.ListWithHandler(query, func(tx *bbolt.Tx, ids []string, qmd *models.QueryMetaData) error {
		for _, id := range ids {
			enrollment, _ := self.readInTx(tx, id)

			if enrollment != nil {
				enrollments = append(enrollments, enrollment)
			}
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return enrollments, nil
}

func (self *EnrollmentManager) EnrollmentToProtobuf(entity *Enrollment) (*edge_cmd_pb.Enrollment, error) {
	tags, err := edge_cmd_pb.EncodeTags(entity.Tags)
	if err != nil {
		return nil, err
	}

	msg := &edge_cmd_pb.Enrollment{
		Id:              entity.Id,
		Tags:            tags,
		Method:          entity.Method,
		IdentityId:      entity.IdentityId,
		TransitRouterId: entity.TransitRouterId,
		EdgeRouterId:    entity.EdgeRouterId,
		Token:           entity.Token,
		IssuedAt:        timePtrToPb(entity.IssuedAt),
		ExpiresAt:       timePtrToPb(entity.ExpiresAt),
		Jwt:             entity.Jwt,
		CaId:            entity.CaId,
		Username:        entity.Username,
	}

	return msg, nil
}

func (self *EnrollmentManager) Marshall(entity *Enrollment) ([]byte, error) {
	msg, err := self.EnrollmentToProtobuf(entity)
	if err != nil {
		return nil, err
	}
	return proto.Marshal(msg)
}

func (self *EnrollmentManager) ProtobufToEnrollment(msg *edge_cmd_pb.Enrollment) (*Enrollment, error) {
	return &Enrollment{
		BaseEntity: models.BaseEntity{
			Id:   msg.Id,
			Tags: edge_cmd_pb.DecodeTags(msg.Tags),
		},
		Method:          msg.Method,
		IdentityId:      msg.IdentityId,
		TransitRouterId: msg.TransitRouterId,
		EdgeRouterId:    msg.EdgeRouterId,
		Token:           msg.Token,
		IssuedAt:        pbTimeToTimePtr(msg.IssuedAt),
		ExpiresAt:       pbTimeToTimePtr(msg.ExpiresAt),
		Jwt:             msg.Jwt,
		CaId:            msg.CaId,
		Username:        msg.Username,
	}, nil
}

func (self *EnrollmentManager) Unmarshall(bytes []byte) (*Enrollment, error) {
	msg := &edge_cmd_pb.Enrollment{}
	if err := proto.Unmarshal(bytes, msg); err != nil {
		return nil, err
	}
	return self.ProtobufToEnrollment(msg)
}

type ReplaceEnrollmentWithAuthenticatorCmd struct {
	manager       *EnrollmentManager
	enrollmentId  string
	authenticator *Authenticator
}

func (self *ReplaceEnrollmentWithAuthenticatorCmd) Apply() error {
	return self.manager.ApplyReplaceEncoderWithAuthenticatorCommand(self)
}

func (self *ReplaceEnrollmentWithAuthenticatorCmd) Encode() ([]byte, error) {
	authMsg, err := self.manager.GetEnv().GetManagers().Authenticator.AuthenticatorToProtobuf(self.authenticator)
	if err != nil {
		return nil, err
	}

	cmd := &edge_cmd_pb.ReplaceEnrollmentWithAuthenticatorCmd{
		EnrollmentId:  self.enrollmentId,
		Authenticator: authMsg,
	}
	return cmd_pb.EncodeProtobuf(cmd)
}

func (self *ReplaceEnrollmentWithAuthenticatorCmd) Decode(env Env, msg *edge_cmd_pb.ReplaceEnrollmentWithAuthenticatorCmd) error {
	self.manager = env.GetManagers().Enrollment
	self.enrollmentId = msg.EnrollmentId
	authenticator, err := env.GetManagers().Authenticator.ProtobufToAuthenticator(msg.Authenticator)
	if err != nil {
		return err
	}
	self.authenticator = authenticator
	return nil
}
