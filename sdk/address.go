package sdk

import "strings"

type Intent struct {
	Type string            `json:"type"`
	Args map[string]string `json:"args"`
}

type Sender struct {
	Address              Address   `json:"id"`
	RequiredAuths        []Address `json:"required_auths"`
	RequiredPostingAuths []Address `json:"required_posting_auths"`
}

//tinyjson:json
type ContractCallOptions struct {
	Intents []Intent `json:"intents,omitempty"`
}

type AddressDomain string

const (
	AddressDomainUser     AddressDomain = "user"
	AddressDomainContract AddressDomain = "contract"
	AddressDomainSystem   AddressDomain = "system"
	AddressDomainKey      AddressDomain = "key"
	AddressDomainUnknown  AddressDomain = "unknown"
)

type Address string

func (a Address) String() string {
	return string(a)
}

func (a Address) Domain() AddressDomain {
	addressType := VerifyAddress(a.String())
	addressDomain := strings.Split(addressType, ":")[0]
	return AddressDomain(addressDomain)
}

func (a Address) IsValid() bool {
	return VerifyAddress(a.String()) != string(AddressDomainUnknown)
}
