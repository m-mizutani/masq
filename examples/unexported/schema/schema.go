package schema

import "github.com/aws/jsii-runtime-go"

type Request struct {
	input
}

type input struct {
	Trigger    *trigger  `json:"trigger"`
	UseSecrets *bool     `json:"use_secrets"`
	Secrets    *[]secret `json:"individual_secrets"`
}

type trigger struct {
	Id string `json:"id"`
}

type secret struct {
	Key string `json:"key"`
}

func CreateRequest() Request {
	return Request{
		input{
			Trigger: &trigger{
				Id: "example-trigger-id",
			},
			UseSecrets: jsii.Bool(true),
			Secrets: &[]secret{
				{
					Key: "example-key",
				},
			},
		},
	}
}