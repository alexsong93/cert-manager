// Package dyn implements a DNS provider for solving the DNS-01
// challenge using dyn DNS.
package dyn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
	pkgutil "github.com/jetstack/cert-manager/pkg/util"
)

// ZONE dns zone to query
var ZONE = os.Getenv("DYN_ZONE") // eg. apiconnect.cloud.ibm.com

// DynAPIUrl represents the API endpoint to call.
const DynAPIUrl = "https://api.dynect.net"

// DNSProvider is an implementation of the acme.ChallengeProvider interface
type DNSProvider struct {
	customerName string
	userName     string
	password     string
}

// NewDNSProvider returns a DNSProvider instance configured for dyn.
// Credentials must be passed in the environment variables: DYN_CUSTOMER_NAME
// and DYN_USER_NAME and DYN_PASSWORD.
func NewDNSProvider() (*DNSProvider, error) {
	customerName := os.Getenv("DYN_CUSTOMER_NAME")
	userName := os.Getenv("DYN_USER_NAME")
	password := os.Getenv("DYN_PASSWORD")

	if customerName == "" || userName == "" || password == "" {
		return nil, fmt.Errorf("Dyn credentials missing")
	}

	return &DNSProvider{
		customerName: customerName,
		userName:     userName,
		password:     password,
	}, nil
}

// Timeout returns the timeout and interval to use when checking for DNS
// propagation. Adjusting here to cope with spikes in propagation times.
func (c *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return 120 * time.Second, 2 * time.Second
}

// Present creates a TXT record to fulfil the dns-01 challenge
func (c *DNSProvider) Present(domain, token, keyAuth string) error {
	// Login, start session, and get auth token
	authToken, err := c.login()
	if err != nil {
		return err
	}
	// Find Text record for fqdn
	fqdn, txtValue, _ := util.DNS01Record(domain, keyAuth)
	record, err := c.findTxtRecord(fqdn, authToken)
	if err != nil && err != errNoExistingRecord {
		return err
	}
	// Create or update Text record
	type Rdata struct {
		Txtdata string `json:"txtdata"`
	}
	type UpdateRequest struct {
		Rdata Rdata `json:"rdata"`
		TTL   int   `json:"ttl"`
	}
	updateRequestObj, err := json.Marshal(UpdateRequest{
		Rdata: Rdata{
			Txtdata: txtValue,
		},
		TTL: 60,
	})
	if err != nil {
		return err
	}
	if record != nil {
		if record.Txtdata == txtValue {
			// the record is already set to the desired value
			return nil
		}
		// Update existing record
		_, err = c.makeRequest("PUT", fmt.Sprintf("/REST/TXTRecord/%s/%s/%d", ZONE, fqdn, record.ID), bytes.NewReader(updateRequestObj), authToken)
		if err != nil {
			return err
		}
	} else {
		// Create existing record
		_, err = c.makeRequest("POST", fmt.Sprintf("/REST/TXTRecord/%s/%s/%d", ZONE, fqdn, record.ID), bytes.NewReader(updateRequestObj), authToken)
		if err != nil {
			return err
		}
	}
	// Publish zone
	type PublishRequest struct {
		Publish string `json:"publish"`
	}
	publishRequestObj, err := json.Marshal(PublishRequest{
		Publish: "true",
	})
	_, err = c.makeRequest("PUT", fmt.Sprintf("/REST/Zone/%s", ZONE), bytes.NewReader(publishRequestObj), authToken)
	if err != nil {
		return err
	}
	// Logout and close session
	err = c.logout(authToken)
	if err != nil {
		return err
	}
	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (c *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	// Login, start session, and get auth token
	authToken, err := c.login()
	if err != nil {
		return err
	}
	// Find Text record for fqdn
	fqdn, _, _ := util.DNS01Record(domain, keyAuth)
	record, err := c.findTxtRecord(fqdn, authToken)
	if err != nil {
		return err
	}
	// Remove Text record
	_, err = c.makeRequest("DELETE", fmt.Sprintf("/REST/TXTRecord/%s/%s/%d", ZONE, fqdn, record.ID), nil, authToken)
	if err != nil {
		return err
	}
	// Logout and close session
	err = c.logout(authToken)
	if err != nil {
		return err
	}
	return nil
}

func (c *DNSProvider) login() (string, error) {
	credsObj, err := json.Marshal(dynLoginCreds{
		CustomerName: c.customerName,
		UserName:     c.userName,
		Password:     c.password,
	})
	if err != nil {
		return "", err
	}
	result, err := c.makeRequest("POST", "/REST/Session", bytes.NewReader(credsObj), "")
	if err != nil {
		return "", err
	}
	var credsResponse map[string]interface{}
	err = json.Unmarshal(result, &credsResponse)
	if err != nil {
		return "", err
	}
	authToken := credsResponse["data"].(map[string]interface{})["token"].(string)
	return authToken, nil
}

func (c *DNSProvider) logout(authToken string) error {
	_, err := c.makeRequest("DELETE", "/REST/Session", nil, authToken)
	return err
}

var errNoExistingRecord = errors.New("No existing record found")

func (c *DNSProvider) findTxtRecord(fqdn string, authToken string) (*dynRecord, error) {
	// Get all txt records for fqdn
	result, err := c.makeRequest("GET", fmt.Sprintf("/TXTRecord/%s/%s", ZONE, util.UnFqdn(fqdn)), nil, authToken)
	if err != nil {
		return nil, err
	}
	var recordsObj map[string]interface{}
	err = json.Unmarshal(result, &recordsObj)
	if err != nil {
		return nil, err
	}
	records := recordsObj["data"].([]string)
	if len(records) == 0 {
		return nil, errNoExistingRecord
	}
	// Get specific txt record for fqdn
	recordURI := records[0]
	result, err = c.makeRequest("GET", recordURI, nil, authToken)
	if err != nil {
		return nil, err
	}
	var record map[string]interface{}
	json.Unmarshal(result, &record)
	id := record["data"].(map[string]interface{})["record_id"].(int)
	txtdata := record["data"].(map[string]interface{})["rdata"].(map[string]interface{})["txtdata"].(string)
	ttl := record["data"].(map[string]interface{})["ttl"].(int)
	return &dynRecord{
		ID:      id,
		Txtdata: txtdata,
		Zone:    ZONE,
		FQDN:    fqdn,
		TTL:     ttl,
	}, nil
}

func (c *DNSProvider) makeRequest(method, uri string, body io.Reader, authToken string) ([]byte, error) {
	req, err := http.NewRequest(method, fmt.Sprintf("%s%s", DynAPIUrl, uri), body)
	req.Header.Set("Auth-Token", authToken)
	req.Header.Set("User-Agent", pkgutil.CertManagerUserAgent)
	client := http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("Error querying Dyn API -> %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Dyn API returned %d %s", resp.StatusCode, resp.Status)
	}
	responsePayload, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("Failed to read response payload -> %v", err)
	}
	return responsePayload, nil
}

// dynLoginCreds represents Dyn Login Credentials object
type dynLoginCreds struct {
	CustomerName string `json:"customerName"`
	UserName     string `json:"userName"`
	Password     string `json:"password"`
}

// dynRecord represents a Dyn DNS record
type dynRecord struct {
	ID      int    `json:"id"`
	Txtdata string `json:"txtdata"`
	Zone    string `json:"zone"`
	FQDN    string `json:"fqdn"`
	TTL     int    `json:"ttl,omitempty"`
}
