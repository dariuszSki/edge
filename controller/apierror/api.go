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

package apierror

import (
	"fmt"
	"github.com/Jeffail/gabs"
	"github.com/go-openapi/errors"
	"github.com/openziti/edge/controller/schema"
	"github.com/openziti/edge/rest_model"
	"github.com/openziti/foundation/util/errorz"
)

func ToRestModel(e *errorz.ApiError, requestId string) *rest_model.APIError {
	ret := &rest_model.APIError{
		Args:      nil,
		Code:      e.Code,
		Message:   e.Message,
		RequestID: requestId,
	}

	if e.Cause != nil {

		//unwrap first error in composite error
		compositeErr, ok := e.Cause.(*errors.CompositeError)
		for ok {
			e.Cause = compositeErr.Errors[0]
			compositeErr, ok = e.Cause.(*errors.CompositeError)
		}

		if causeApiError, ok := e.Cause.(*errorz.ApiError); ok {
			//standard apierror
			ret.Cause = &rest_model.APIErrorCause{
				APIError: *ToRestModel(causeApiError, requestId),
			}
		} else if causeJsonSchemaError, ok := e.Cause.(*schema.ValidationErrors); ok {
			//only possible from config type JSON schema validation
			ret.Cause = &rest_model.APIErrorCause{
				APIFieldError: rest_model.APIFieldError{
					Field:  causeJsonSchemaError.Errors[0].Field,
					Reason: causeJsonSchemaError.Errors[0].Error(),
					Value:  fmt.Sprintf("%v", causeJsonSchemaError.Errors[0].Value),
				},
			}
		} else if causeFieldErr, ok := e.Cause.(*errorz.FieldError); ok {
			//authenticator modules and enrollment only
			//todo: see if we can remove this by not using FieldError
			ret.Cause = &rest_model.APIErrorCause{
				APIFieldError: rest_model.APIFieldError{
					Field:  causeFieldErr.FieldName,
					Value:  fmt.Sprintf("%v", causeFieldErr.FieldValue),
					Reason: causeFieldErr.Reason,
				},
			}
			if ret.Code == errorz.InvalidFieldCode {
				ret.Code = errorz.CouldNotValidateCode
				ret.Message = errorz.CouldNotValidateMessage
			}

		} else if causeFieldErr, ok := e.Cause.(*errors.Validation); ok {
			//open api validation errors
			ret.Cause = &rest_model.APIErrorCause{
				APIFieldError: rest_model.APIFieldError{
					Field:  causeFieldErr.Name,
					Reason: causeFieldErr.Error(),
					Value:  fmt.Sprintf("%v", causeFieldErr.Value),
				},
			}
			ret.Code = errorz.CouldNotValidateCode
			ret.Message = errorz.CouldNotValidateMessage

		} else if genericErr, ok := e.Cause.(GenericCauseError); ok {
			ret.Cause = &rest_model.APIErrorCause{
				APIError: rest_model.APIError{
					Data:    genericErr.DataMap,
					Message: genericErr.Error(),
				},
			}
		} else {
			ret.Cause = &rest_model.APIErrorCause{
				APIError: rest_model.APIError{
					Code:    errorz.UnhandledCode,
					Message: e.Cause.Error(),
				},
			}
		}

	}

	return ret
}

type GenericCauseError struct {
	Message string
	DataMap map[string]interface{}
}

func (e GenericCauseError) Error() string {
	return e.Message
}

func (e *GenericCauseError) MarshalJSON() ([]byte, error) {
	data, err := gabs.Consume(e.DataMap) //gabs to avoid zero values being omitted

	if err != nil {
		return nil, err
	}

	return data.Bytes(), nil
}
