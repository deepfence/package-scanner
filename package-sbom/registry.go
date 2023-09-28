package package_sbom

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/deepfence/package-scanner/util"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	log "github.com/sirupsen/logrus"
)

var (
	api_service_host = util.GetEnv("API_SERVICE_HOST", "deepfence-api")
	api_service_port = util.GetEnv("API_SERVICE_PORT_INTERNAL", "9997")
	api_service_url  = fmt.Sprintf("http://%s:%s", api_service_host, api_service_port)
)

type registryCredentialResponse struct {
	Data    map[string]interface{} `json:"data,omitempty"`
	Error   interface{}            `json:"error,omitempty"`
	Success bool                   `json:"success,omitempty"`
}

func callRegistryCredentialApi(registryId string) (registryCredentialResponse, error) {
	var registryCredentialsOutput registryCredentialResponse
	client := &http.Client{}
	req, err := http.NewRequest("POST", api_service_url+"/registry_credential",
		bytes.NewBuffer([]byte(`{"id":"`+registryId+`"}`)))
	if err != nil {
		return registryCredentialsOutput, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return registryCredentialsOutput, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return registryCredentialsOutput, err
	}
	err = json.Unmarshal(body, &registryCredentialsOutput)
	if err != nil {
		return registryCredentialsOutput, err
	}
	return registryCredentialsOutput, err
}

func isRegistryInsecure(registryId string) bool {
	registryData, err := callRegistryCredentialApi(registryId)
	if err != nil || !registryData.Success {
		log.Error("unable to get registry credentials")
		return false
	}
	if registryData.Data == nil {
		log.Error("invalid registry credentials obtained from API")
		return false
	}
	registryUrl, _, _ := GetDockerCredentials(registryData.Data)

	if strings.Contains(registryUrl, "http:") {
		return true
	}
	return false
}

func GetConfigFileFromRegistry(registryId string) (string, error) {
	registryUrl, username, password, err := GetCredentialsFromRegistry(registryId)
	if username == "" {
		return "", nil
	}
	authFile, err := createAuthFile(registryId, registryUrl, username, password)
	if err != nil {
		return "", fmt.Errorf("unable to create credential file for docker")
	}
	return authFile, nil
}

func GetCredentialsFromRegistry(registryId string) (string, string, string, error) {
	registryData, err := callRegistryCredentialApi(registryId)
	if err != nil || !registryData.Success {
		return "", "", "", fmt.Errorf("unable to get registry credentials")
	}
	if registryData.Data == nil {
		return "", "", "", fmt.Errorf("invalid registry credentials obtained from API")
	}
	registryUrl, username, password := GetDockerCredentials(registryData.Data)

	if username == "" {
		return "", "", "", fmt.Errorf("unable to get credentials for specified registry")
	}
	if password == "" {
		decodedBytes, err := base64.StdEncoding.DecodeString(username)
		if err != nil {
			return "", "", "", fmt.Errorf("invalid credentials for specified registry")
		}
		splitCredentials := strings.Split(string(decodedBytes), ":")
		if len(splitCredentials) != 2 {
			return "", "", "", fmt.Errorf("invalid credentials for specified registry")
		}
		username = splitCredentials[0]
		password = splitCredentials[1]
	}
	return registryUrl, username, password, nil
}

func GetDockerCredentials(registryData map[string]interface{}) (string, string, string) {
	var registryType string
	registryType, ok := registryData["registry_type"].(string)
	if !ok {
		return "", "", ""
	}
	switch registryType {
	case "ecr":
		var awsAccessKey, awsSecret, awsRegionName, registryId, targetAccountRoleARN string
		var useIAMRole bool
		if awsAccessKey, ok = registryData["aws_access_key_id"].(string); !ok {
			awsAccessKey = ""
		}
		if awsSecret, ok = registryData["aws_secret_access_key"].(string); !ok {
			awsSecret = ""
		}
		if awsRegionName, ok = registryData["aws_region_name"].(string); !ok {
			return "", "", ""
		}
		if registryId, ok = registryData["registry_id"].(string); !ok {
			registryId = ""
		}
		if useIAMRole, ok = registryData["use_iam_role"].(bool); !ok {
			useIAMRole = false
		}
		if targetAccountRoleARN, ok = registryData["target_account_role_arn"].(string); !ok {
			targetAccountRoleARN = ""
		}
		ecrProxyUrl, ecrAuth := getEcrCredentials(awsAccessKey, awsSecret, awsRegionName, registryId, useIAMRole, targetAccountRoleARN)
		return ecrProxyUrl, ecrAuth, ""
	case "docker_hub":
		var dockerUsername, dockerPassword string
		if dockerUsername, ok = registryData["docker_hub_username"].(string); !ok {
			return "", "", ""
		}
		if dockerPassword, ok = registryData["docker_hub_password"].(string); !ok {
			return "", "", ""
		}
		return "https://index.docker.io/v1/", dockerUsername, dockerPassword
	case "docker_private_registry":
		return getDefaultDockerCredentials(registryData, "docker_registry_url", "docker_username", "docker_password")
	case "azure_container_registry":
		return getDefaultDockerCredentials(registryData, "azure_registry_url", "azure_registry_username", "azure_registry_password")
	case "google_container_registry":
		var dockerPassword, registryUrl string
		if dockerPassword, ok = registryData["service_account_json"].(string); !ok {
			return "", "", ""
		}
		if registryUrl, ok = registryData["registry_hostname"].(string); !ok {
			return "", "", ""
		}
		return registryUrl, "_json_key", dockerPassword
	case "harbor":
		return getDefaultDockerCredentials(registryData, "harbor_registry_url", "harbor_username", "harbor_password")
	case "quay":
		var dockerPassword, registryUrl string
		if dockerPassword, ok = registryData["quay_access_token"].(string); !ok {
			return "", "", ""
		}
		if registryUrl, ok = registryData["quay_registry_url"].(string); !ok {
			return "", "", ""
		}
		return registryUrl, "$oauthtoken", dockerPassword
	case "gitlab":
		var dockerPassword, registryUrl string
		if dockerPassword, ok = registryData["gitlab_access_token"].(string); !ok {
			return "", "", ""
		}
		if registryUrl, ok = registryData["gitlab_registry_url"].(string); !ok {
			return "", "", ""
		}
		return registryUrl, "gitlab-ci-token", dockerPassword
	case "jfrog_container_registry":
		return getDefaultDockerCredentials(registryData, "jfrog_registry_url", "jfrog_username", "jfrog_password")
	default:
		return "", "", ""
	}
}

func getDefaultDockerCredentials(registryData map[string]interface{}, registryUrlKey, registryUsernameKey, registryPasswordKey string) (string, string, string) {
	var dockerUsername, dockerPassword, dockerRegistryUrl string
	var ok bool
	if dockerUsername, ok = registryData[registryUsernameKey].(string); !ok {
		return "", "", ""
	}
	if dockerPassword, ok = registryData[registryPasswordKey].(string); !ok {
		return "", "", ""
	}
	if dockerRegistryUrl, ok = registryData[registryUrlKey].(string); !ok {
		return "", "", ""
	}
	return dockerRegistryUrl, dockerUsername, dockerPassword
}

func createAuthFile(registryId, registryUrl, username, password string) (string, error) {
	authFilePath := "/tmp/auth_" + registryId + "_" + util.RandomString(12)
	if _, err := os.Stat(authFilePath); errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(authFilePath, os.ModePerm)
		if err != nil {
			return "", err
		}
	}
	if password == "" {
		configJson := []byte("{\"auths\": {\"" + registryUrl + "\": {\"auth\": \"" + strings.ReplaceAll(username, "\"", "\\\"") + "\"} } }")
		err := os.WriteFile(authFilePath+"/config.json", configJson, 0644)
		if err != nil {
			return "", err
		}
	} else {
		configJson := []byte("{\"auths\": {\"" + registryUrl + "\": {\"auth\": \"" + base64.StdEncoding.EncodeToString([]byte(username+":"+password)) + "\"} } }")
		err := os.WriteFile(authFilePath+"/config.json", configJson, 0644)
		if err != nil {
			return "", err
		}
	}
	return authFilePath, nil
}

func getEcrCredentials(awsAccessKey, awsSecret, awsRegionName, registryId string, useIAMRole bool, targetAccountRoleARN string) (string, string) {
	var awsConfig aws.Config
	var svc *ecr.ECR
	var creds *credentials.Credentials

	if !useIAMRole {
		awsConfig.WithCredentials(credentials.NewStaticCredentials(awsAccessKey, awsSecret, ""))
	}
	mySession := session.Must(session.NewSession(&awsConfig))

	if useIAMRole {
		if targetAccountRoleARN == "" {
			svc = ecr.New(mySession, aws.NewConfig().WithRegion(awsRegionName))
		} else {
			creds = stscreds.NewCredentials(mySession, targetAccountRoleARN)
			svc = ecr.New(mySession, &aws.Config{
				Credentials: creds,
				Region:      &awsRegionName,
			})
		}
	} else {
		svc = ecr.New(mySession, aws.NewConfig().WithRegion(awsRegionName))
	}

	var authorizationTokenRequestInput ecr.GetAuthorizationTokenInput
	if registryId != "" {
		authorizationTokenRequestInput.SetRegistryIds([]*string{&registryId})
	}
	authorizationTokenResponse, err := svc.GetAuthorizationToken(&authorizationTokenRequestInput)
	if err != nil {
		return "", ""
	}
	authorizationData := authorizationTokenResponse.AuthorizationData
	if len(authorizationData) == 0 {
		return "", ""
	}
	authData := *authorizationData[0]
	return *authData.ProxyEndpoint, *authData.AuthorizationToken
}
