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
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"github.com/dgryski/dgoogauth"
	"github.com/openziti/edge/controller/apierror"
	"github.com/openziti/edge/controller/persistence"
	"github.com/openziti/edge/pb/edge_cmd_pb"
	"github.com/openziti/fabric/controller/command"
	"github.com/openziti/fabric/controller/fields"
	"github.com/openziti/fabric/controller/models"
	"github.com/openziti/fabric/controller/network"
	"github.com/openziti/foundation/v2/errorz"
	"github.com/openziti/storage/boltz"
	"github.com/pkg/errors"
	"github.com/skip2/go-qrcode"
	"go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
	"strings"
)

const (
	WindowSizeTOTP int = 5
)

func NewMfaManager(env Env) *MfaManager {
	manager := &MfaManager{
		baseEntityManager: newBaseEntityManager(env, env.GetStores().Mfa),
	}
	manager.impl = manager

	network.RegisterManagerDecoder[*Mfa](env.GetHostController().GetNetwork().Managers, manager)

	return manager
}

type MfaManager struct {
	baseEntityManager
}

func (self *MfaManager) newModelEntity() edgeEntity {
	return &Mfa{}
}

func (self *MfaManager) CreateForIdentity(identity *Identity) (string, error) {
	secretBytes := make([]byte, 10)
	_, _ = rand.Read(secretBytes)
	secret := base32.StdEncoding.EncodeToString(secretBytes)

	recoveryCodes := self.generateRecoveryCodes()

	mfa := &Mfa{
		BaseEntity:    models.BaseEntity{},
		IsVerified:    false,
		IdentityId:    identity.Id,
		Identity:      identity,
		Secret:        secret,
		RecoveryCodes: recoveryCodes,
	}

	err := self.Create(mfa)
	if err != nil {
		return "", err
	}
	return mfa.Id, err
}

func (self *MfaManager) Create(entity *Mfa) error {
	return network.DispatchCreate[*Mfa](self, entity)
}

func (self *MfaManager) ApplyCreate(cmd *command.CreateEntityCommand[*Mfa]) error {
	_, err := self.createEntity(cmd.Entity)
	return err
}

func (self *MfaManager) Update(entity *Mfa, checker fields.UpdatedFields) error {
	return network.DispatchUpdate[*Mfa](self, entity, checker)
}

func (self *MfaManager) ApplyUpdate(cmd *command.UpdateEntityCommand[*Mfa]) error {
	var checker boltz.FieldChecker = self
	if cmd.UpdatedFields != nil {
		checker = &AndFieldChecker{first: self, second: cmd.UpdatedFields}
	}
	return self.updateEntity(cmd.Entity, checker)
}

func (self *MfaManager) Read(id string) (*Mfa, error) {
	modelMfa := &Mfa{}
	if err := self.readEntity(id, modelMfa); err != nil {
		return nil, err
	}
	return modelMfa, nil
}

func (self *MfaManager) readInTx(tx *bbolt.Tx, id string) (*Mfa, error) {
	modelMfa := &Mfa{}
	if err := self.readEntityInTx(tx, id, modelMfa); err != nil {
		return nil, err
	}
	return modelMfa, nil
}

func (self *MfaManager) IsUpdated(field string) bool {
	return field == persistence.FieldMfaIsVerified || field == persistence.FieldMfaRecoveryCodes
}

func (self *MfaManager) Query(query string) (*MfaListResult, error) {
	result := &MfaListResult{manager: self}
	err := self.ListWithHandler(query, result.collect)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (self *MfaManager) ReadByIdentityId(identityId string) (*Mfa, error) {
	query := fmt.Sprintf(`identity = "%s"`, identityId)

	resultList, err := self.Query(query)

	if err != nil {
		return nil, err
	}

	if resultList.Count > 1 {
		return nil, fmt.Errorf("too many MFAs associated to a single identity, expected 1 got %d for identityId %s", resultList.Count, identityId)
	}

	if resultList.Count == 0 {
		return nil, nil
	}

	return resultList.Mfas[0], nil
}

func (self *MfaManager) Verify(mfa *Mfa, code string) (bool, error) {
	//check recovery codes
	for i, recoveryCode := range mfa.RecoveryCodes {
		if recoveryCode == code {
			mfa.RecoveryCodes = append(mfa.RecoveryCodes[:i], mfa.RecoveryCodes[i+1:]...)
			if err := self.Update(mfa, nil); err != nil {
				return false, err
			}
			return true, nil
		}
	}

	return self.VerifyTOTP(mfa, code)
}

// VerifyTOTP verifies TOTP values only, not recovery codes
func (self *MfaManager) VerifyTOTP(mfa *Mfa, code string) (bool, error) {
	otp := dgoogauth.OTPConfig{
		Secret:     mfa.Secret,
		WindowSize: WindowSizeTOTP,
		UTC:        true,
	}

	return otp.Authenticate(code)
}

func (self *MfaManager) DeleteForIdentity(identity *Identity, code string) error {
	mfa, err := self.ReadByIdentityId(identity.Id)

	if err != nil {
		return err
	}

	if mfa == nil {
		return errorz.NewNotFound()
	}

	if mfa.IsVerified {
		//if MFA is enabled require a valid code
		valid, err := self.Verify(mfa, code)

		if err != nil || !valid {
			return apierror.NewInvalidMfaTokenError()
		}
	}

	if err = self.Delete(mfa.Id); err != nil {
		return err
	}

	return nil
}

func (self *MfaManager) QrCodePng(mfa *Mfa) ([]byte, error) {
	if mfa.IsVerified {
		return nil, fmt.Errorf("MFA is already verified")
	}

	url := self.GetProvisioningUrl(mfa)

	return qrcode.Encode(url, qrcode.Medium, 256)
}

func (self *MfaManager) GetProvisioningUrl(mfa *Mfa) string {
	otcConfig := &dgoogauth.OTPConfig{
		Secret:     mfa.Secret,
		WindowSize: WindowSizeTOTP,
		UTC:        true,
	}
	return otcConfig.ProvisionURIWithIssuer(mfa.Identity.Name, "ziti.dev")
}

func (self *MfaManager) RecreateRecoveryCodes(mfa *Mfa) error {
	newCodes := self.generateRecoveryCodes()

	mfa.RecoveryCodes = newCodes

	return self.Update(mfa, nil)
}

func (self *MfaManager) generateRecoveryCodes() []string {
	recoveryCodes := []string{}

	for i := 0; i < 20; i++ {
		backupBytes := make([]byte, 8)
		rand.Read(backupBytes)
		backupStr := base32.StdEncoding.EncodeToString(backupBytes)
		backupCode := strings.Replace(backupStr, "=", "", -1)[:6]
		recoveryCodes = append(recoveryCodes, backupCode)
	}

	return recoveryCodes
}

func (self *MfaManager) Marshall(entity *Mfa) ([]byte, error) {
	tags, err := edge_cmd_pb.EncodeTags(entity.Tags)
	if err != nil {
		return nil, err
	}

	msg := &edge_cmd_pb.Mfa{
		Id:            entity.Id,
		Tags:          tags,
		IsVerified:    entity.IsVerified,
		IdentityId:    entity.IdentityId,
		Secret:        entity.Secret,
		RecoveryCodes: entity.RecoveryCodes,
	}

	return proto.Marshal(msg)
}

func (self *MfaManager) Unmarshall(bytes []byte) (*Mfa, error) {
	msg := &edge_cmd_pb.Mfa{}
	if err := proto.Unmarshal(bytes, msg); err != nil {
		return nil, err
	}

	identity, err := self.env.GetManagers().Identity.Read(msg.IdentityId)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to lookup identity for mfa with id=[%v]", msg.Id)
	}

	return &Mfa{
		BaseEntity: models.BaseEntity{
			Id:   msg.Id,
			Tags: edge_cmd_pb.DecodeTags(msg.Tags),
		},
		IsVerified:    msg.IsVerified,
		IdentityId:    msg.IdentityId,
		Identity:      identity,
		Secret:        msg.Secret,
		RecoveryCodes: msg.RecoveryCodes,
	}, nil
}

type MfaListResult struct {
	manager *MfaManager
	Mfas    []*Mfa
	models.QueryMetaData
}

func (result *MfaListResult) collect(tx *bbolt.Tx, ids []string, queryMetaData *models.QueryMetaData) error {
	result.QueryMetaData = *queryMetaData
	for _, key := range ids {
		Mfa, err := result.manager.readInTx(tx, key)
		if err != nil {
			return err
		}
		result.Mfas = append(result.Mfas, Mfa)
	}
	return nil
}
