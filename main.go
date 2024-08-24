package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/tencentcloud"
	"github.com/go-acme/lego/v4/registration"
	"github.com/robfig/cron/v3"
	"github.com/spf13/viper"
	cdn "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/cdn/v20180606"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/regions"
	ssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
	"log"
	"time"
)

func getConfig() *viper.Viper {
	viper.SetConfigName("config") // name of config file (without extension)
	viper.SetConfigType("yaml")   // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")      // optionally look for config in the working directory
	err := viper.ReadInConfig()   // Find and read the config file
	if err != nil {               // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	return viper.GetViper()
}

type MyUser struct {
	email      string
	regres     *registration.Resource
	privatekey crypto.PrivateKey
}

func (u MyUser) GetEmail() string                        { return u.email }
func (u MyUser) GetRegistration() *registration.Resource { return u.regres }
func (u MyUser) GetPrivateKey() crypto.PrivateKey        { return u.privatekey }

// 获取getChallengeProvider
func getChallengeProvider(providerName string, config *viper.Viper) challenge.Provider {
	// 获取dns provider配置
	dnsProviders := config.Get("dns-providers").([]interface{})
	for _, provider := range dnsProviders {
		providerMap := provider.(map[string]interface{})
		name := providerMap["name"].(string)
		if name == providerName {
			// 找到了对应的provider
			providerType := providerMap["type"].(string)
			switch providerType {
			case "tencentcloud":
				// 腾讯云
				dnsConfig := tencentcloud.NewDefaultConfig()
				dnsConfig.SecretID = providerMap["secret-id"].(string)
				dnsConfig.SecretKey = providerMap["secret-key"].(string)
				providerConfig, _ := tencentcloud.NewDNSProviderConfig(dnsConfig)
				return providerConfig
			case "cloudflare":
				dnsConfig := cloudflare.NewDefaultConfig()
				dnsConfig.AuthEmail = providerMap["auth-email"].(string)
				dnsConfig.AuthKey = providerMap["auth-key"].(string)
				providerConfig, _ := cloudflare.NewDNSProviderConfig(dnsConfig)
				return providerConfig
			default:
				log.Fatalf("Unknown provider type: %s", providerType)
			}
		}
	}
	log.Fatalf("Provider not found: %s", providerName)
	return nil
}

// 申请证书
func obtainCertificate(domain string, providerName string, config *viper.Viper) *certificate.Resource {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	user := MyUser{
		email:      config.GetString("email"),
		regres:     &registration.Resource{},
		privatekey: privateKey,
	}

	legoConfig := lego.NewConfig(&user)

	// 设置 ca服务器地址
	if config.GetBool("debug") {
		legoConfig.CADirURL = lego.LEDirectoryStaging
	} else {
		legoConfig.CADirURL = lego.LEDirectoryProduction
	}

	// 初始化
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		log.Fatal(err)
	}

	// 新用户注册
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	user.regres = reg

	// 设置域名
	request := certificate.ObtainRequest{
		Domains: []string{domain},
		Bundle:  true,
	}

	// 设置DNS01Provider : https://github.com/go-acme/lego/blob/29e98f8a4336fb1f81a7e1671cf48723536f3dd8/cmd/setup_challenges.go#L129
	recursiveNameservers := config.GetStringSlice("recursive-nameservers")
	dnsTimeout := config.GetInt64("dns-timeout")
	err = client.Challenge.SetDNS01Provider(getChallengeProvider(providerName, config),
		dns01.AddRecursiveNameservers(dns01.ParseNameservers(recursiveNameservers)),
		dns01.CondOption(config.GetBool("disable-cp"), dns01.DisableCompletePropagationRequirement()),
		dns01.AddDNSTimeout(time.Duration(dnsTimeout)*time.Second),
		dns01.WrapPreCheck(func(domain, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
			validSleepTime := config.GetInt64("valid-sleep-time")
			log.Printf("Sleep %d seconds to wait for DNS record to take effect", validSleepTime)
			time.Sleep(time.Duration(validSleepTime) * time.Second)
			return check(fqdn, value)
		}),
	)
	if err != nil {
		log.Fatal(err)
	}

	// 获取证书
	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	return certificates
}

func job() {
	config := getConfig()
	renewDays := config.GetInt("renew-days")

	// 获取要续签的证书列表
	renewDomains := config.Get("renew-domains").([]interface{})
	domainProviderMap := make(map[string]string)

	for _, domain := range renewDomains {
		domainMap := domain.(map[string]interface{})
		domainName := domainMap["domain-name"].(string)
		dnsProviderName := domainMap["dns-provider-name"].(string)
		domainProviderMap[domainName] = dnsProviderName
	}

	// 打印出domainProviderMap以验证结果
	for domain, provider := range domainProviderMap {
		fmt.Printf("Domain: %s, Provider: %s\n", domain, provider)
	}

	tencentcloudCredential := common.NewCredential(
		config.GetString("tencentcloud.secret-id"),
		config.GetString("tencentcloud.secret-key"),
	)

	// 获取cdn域名列表
	cdnClient, _ := cdn.NewClient(tencentcloudCredential, regions.Guangzhou, profile.NewClientProfile())
	cdnRequest := cdn.NewDescribeDomainsConfigRequest()
	cdnResponse, err := cdnClient.DescribeDomainsConfig(cdnRequest)
	if _, ok := err.(*errors.TencentCloudSDKError); ok {
		fmt.Printf("An API error has returned: %s", err)
		return
	}
	if err != nil {
		panic(err)
	}

	for _, domain := range cdnResponse.Response.Domains {
		if domainProviderMap[*domain.Domain] != "" {
			// 是需要续签的域名
			if domain.Https.CertInfo != nil {
				// 有证书：判断证书需要续签
				expireTime, _ := time.Parse(time.DateTime, *domain.Https.CertInfo.ExpireTime)
				if time.Now().AddDate(0, 0, renewDays).Before(expireTime) {
					// 证书不需要续签
					continue
				}
				fmt.Printf("[需要续签] Domain: %s, Provider: %s, Cert Expire Time: %s\n", *domain.Domain, domainProviderMap[*domain.Domain], *domain.Https.CertInfo.ExpireTime)
			}
			// 无证书或者证书需要续签

			// 申请证书
			certificates := obtainCertificate(*domain.Domain, domainProviderMap[*domain.Domain], config)

			// 上传证书
			sslClient, _ := ssl.NewClient(tencentcloudCredential, regions.Guangzhou, profile.NewClientProfile())
			uploadCertificateRequest := ssl.NewUploadCertificateRequest()
			uploadCertificateRequest.CertificatePublicKey = common.StringPtr(string(certificates.Certificate))
			uploadCertificateRequest.CertificatePrivateKey = common.StringPtr(string(certificates.PrivateKey))
			uploadCertificateRequest.Alias = common.StringPtr(*domain.Domain + " " + time.Now().Format(time.DateOnly))
			uploadCertificateResponse, err := sslClient.UploadCertificate(uploadCertificateRequest)
			if _, ok := err.(*errors.TencentCloudSDKError); ok {
				fmt.Printf("An API error has returned: %s", err)
				return
			}
			if err != nil {
				panic(err)
			}
			fmt.Printf("Upload Certificate Response: %s\n", uploadCertificateResponse.ToJsonString())

			// 更新域名cdn的证书
			deployCertificateInstanceRequest := ssl.NewDeployCertificateInstanceRequest()
			deployCertificateInstanceRequest.CertificateId = uploadCertificateResponse.Response.CertificateId
			deployCertificateInstanceRequest.InstanceIdList = []*string{common.StringPtr(*domain.Domain)}
			deployCertificateInstanceRequest.ResourceType = common.StringPtr("cdn")
			deployCertificateInstanceResponse, err := sslClient.DeployCertificateInstance(deployCertificateInstanceRequest)
			if _, ok := err.(*errors.TencentCloudSDKError); ok {
				fmt.Printf("An API error has returned: %s", err)
				return
			}
			if err != nil {
				panic(err)
			}
			fmt.Printf("Deploy Certificate Instance Response: %s\n", deployCertificateInstanceResponse.ToJsonString())
		}
	}

}

func main() {
	// 创建一个新的Cron实例
	c := cron.New()

	// 首次执行一次
	job()

	// 定时执行
	config := getConfig()
	_, err := c.AddFunc(config.GetString("cron"), job)

	// 检查是否有错误
	if err != nil {
		fmt.Println("Error scheduling job:", err)
		return
	}

	// 启动定时任务
	c.Start()

	// 主程序进入无限循环，这样定时任务就可以持续运行
	select {}
}
