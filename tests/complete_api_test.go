package tests

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/luoying/gin-hander/conf"
	"github.com/luoying/gin-hander/pkg/api"
	"github.com/luoying/gin-hander/pkg/auth"
	"github.com/luoying/gin-hander/pkg/rsautils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 测试配置
var (
	testServer  *httptest.Server
	testConfig  *conf.Config
	testRouter  *gin.Engine
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	testDevices []string
)

// 初始化测试环境
func setupTestEnvironment(t *testing.T) {
	// 设置Gin为测试模式
	gin.SetMode(gin.TestMode)

	// 加载配置
	var err error
	testConfig, err = conf.LoadConfig("../config.toml", func() (*conf.Config, error) {
		return &conf.Config{
			Listen:     ":8080",
			Database:   "../test.db",
			UploadPath: "../uploads",
			ExportPath: "../exports",
		}, nil
	})
	require.NoError(t, err, "加载配置失败")

	// 加载密钥
	privateKeyData, err := os.ReadFile("../private_key.pem")
	require.NoError(t, err, "读取私钥失败")

	privateKey, err = rsautils.ParsePrivateKey(string(privateKeyData))
	require.NoError(t, err, "解析私钥失败")

	publicKeyData, err := os.ReadFile("../public_key.pem")
	require.NoError(t, err, "读取公钥失败")

	publicKey, err = rsautils.ParsePublicKey(string(publicKeyData))
	require.NoError(t, err, "解析公钥失败")

	// 创建路由
	testRouter = gin.New()

	// 创建客户端工作器
	customerWorker, err := api.NewCustomerWorker(testConfig)
	require.NoError(t, err, "创建客户端工作器失败")

	// 挂载路由
	customerGroup := testRouter.Group("/customer")
	customerWorker.Mount(customerGroup)

	// 创建测试服务器
	testServer = httptest.NewServer(testRouter)

	// 初始化测试设备列表
	testDevices = []string{
		"test_device_001",
		"test_device_002",
		"test_device_003",
		"test_device_004",
		"test_device_005",
	}

	t.Logf("测试环境初始化完成，服务器地址: %s", testServer.URL)
}

// 清理测试环境
func teardownTestEnvironment(t *testing.T) {
	if testServer != nil {
		testServer.Close()
	}
	t.Log("测试环境清理完成")
}

// 生成设备token
func generateDeviceToken(deviceID string) (*auth.DeviceToken, error) {
	token := &auth.DeviceToken{
		ID:        deviceID,
		Timestamp: time.Now().Unix(),
	}

	err := token.GenerateSignature(publicKey)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// 创建认证头
func createAuthHeaders(deviceID string) (map[string]string, error) {
	token, err := generateDeviceToken(deviceID)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"LY-Device-ID": token.ID,
		"LY-Timestamp": strconv.FormatInt(token.Timestamp, 10),
		"LY-Signature": token.Signature,
	}, nil
}

// 发送HTTP请求的辅助函数
func sendRequest(t *testing.T, method, path string, body interface{}, headers map[string]string) *http.Response {
	var reqBody io.Reader

	if body != nil {
		jsonData, err := json.Marshal(body)
		require.NoError(t, err, "序列化请求体失败")
		reqBody = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, testServer.URL+path, reqBody)
	require.NoError(t, err, "创建请求失败")

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err, "发送请求失败")

	return resp
}

// TestMain 测试主函数
func TestMain(m *testing.M) {
	// 这里可以做全局的测试初始化
	code := m.Run()
	os.Exit(code)
}

// Test01_DeviceRegistration 测试设备注册功能
func Test01_DeviceRegistration(t *testing.T) {
	setupTestEnvironment(t)
	defer teardownTestEnvironment(t)

	t.Run("单个设备注册", func(t *testing.T) {
		deviceData := map[string]interface{}{
			"device_id": testDevices[0],
			"title":     "测试设备001",
			"enabled":   true,
		}

		resp := sendRequest(t, "POST", "/customer/auth/add", deviceData, nil)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "设备注册应该成功")

		var result map[string]interface{}
		err := json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err, "解析响应失败")

		assert.Equal(t, float64(0), result["err_no"], "错误码应该为0")
		assert.NotNil(t, result["data"], "应该返回设备数据")

		t.Logf("设备注册成功: %+v", result)
	})

	t.Run("批量设备注册", func(t *testing.T) {
		for i := 1; i < len(testDevices); i++ {
			deviceData := map[string]interface{}{
				"device_id": testDevices[i],
				"title":     fmt.Sprintf("测试设备%03d", i+1),
				"enabled":   true,
			}

			resp := sendRequest(t, "POST", "/customer/auth/add", deviceData, nil)
			defer resp.Body.Close()

			assert.Equal(t, http.StatusOK, resp.StatusCode, "设备注册应该成功")

			var result map[string]interface{}
			err := json.NewDecoder(resp.Body).Decode(&result)
			require.NoError(t, err, "解析响应失败")

			assert.Equal(t, float64(0), result["err_no"], "错误码应该为0")

			t.Logf("设备 %s 注册成功", testDevices[i])
		}
	})
}

// Test02_MultiClientConnection 测试多客户端连接建立
func Test02_MultiClientConnection(t *testing.T) {
	setupTestEnvironment(t)
	defer teardownTestEnvironment(t)

	// 先注册所有设备
	for i, deviceID := range testDevices {
		deviceData := map[string]interface{}{
			"device_id": deviceID,
			"title":     fmt.Sprintf("测试设备%03d", i+1),
			"enabled":   true,
		}

		resp := sendRequest(t, "POST", "/customer/auth/add", deviceData, nil)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "设备注册失败")
	}

	t.Run("并发连接测试", func(t *testing.T) {
		var wg sync.WaitGroup
		results := make(chan bool, len(testDevices))

		for _, deviceID := range testDevices {
			wg.Add(1)
			go func(devID string) {
				defer wg.Done()

				headers, err := createAuthHeaders(devID)
				if err != nil {
					t.Errorf("创建认证头失败: %v", err)
					results <- false
					return
				}

				resp := sendRequest(t, "GET", "/customer/device/", nil, headers)
				defer resp.Body.Close()

				success := resp.StatusCode == http.StatusOK
				results <- success

				if success {
					t.Logf("设备 %s 连接成功", devID)
				} else {
					t.Errorf("设备 %s 连接失败，状态码: %d", devID, resp.StatusCode)
				}
			}(deviceID)
		}

		wg.Wait()
		close(results)

		successCount := 0
		for result := range results {
			if result {
				successCount++
			}
		}

		assert.Equal(t, len(testDevices), successCount, "所有设备都应该连接成功")
		t.Logf("多客户端连接测试完成: %d/%d 成功", successCount, len(testDevices))
	})
}

// Test03_FileUploadDownload 测试文件上传和下载功能
func Test03_FileUploadDownload(t *testing.T) {
	setupTestEnvironment(t)
	defer teardownTestEnvironment(t)

	// 注册测试设备
	deviceData := map[string]interface{}{
		"device_id": testDevices[0],
		"title":     "文件传输测试设备",
		"enabled":   true,
	}

	resp := sendRequest(t, "POST", "/customer/auth/add", deviceData, nil)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "设备注册失败")

	t.Run("文件上传测试", func(t *testing.T) {
		// 创建测试文件
		testFileName := "test_upload_file.txt"
		testContent := "这是一个测试文件内容，用于验证文件上传功能。"

		err := os.WriteFile(testFileName, []byte(testContent), 0644)
		require.NoError(t, err, "创建测试文件失败")
		defer os.Remove(testFileName)

		// 创建认证头
		headers, err := createAuthHeaders(testDevices[0])
		require.NoError(t, err, "创建认证头失败")

		// 创建multipart表单
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)

		// 添加文件
		file, err := os.Open(testFileName)
		require.NoError(t, err, "打开测试文件失败")
		defer file.Close()

		part, err := writer.CreateFormFile("file", testFileName)
		require.NoError(t, err, "创建表单文件字段失败")

		_, err = io.Copy(part, file)
		require.NoError(t, err, "复制文件内容失败")

		err = writer.Close()
		require.NoError(t, err, "关闭writer失败")

		// 发送上传请求
		req, err := http.NewRequest("POST", testServer.URL+"/customer/upload/file", &buf)
		require.NoError(t, err, "创建上传请求失败")

		req.Header.Set("Content-Type", writer.FormDataContentType())
		for key, value := range headers {
			req.Header.Set(key, value)
		}

		client := &http.Client{}
		uploadResp, err := client.Do(req)
		require.NoError(t, err, "发送上传请求失败")
		defer uploadResp.Body.Close()

		assert.Equal(t, http.StatusOK, uploadResp.StatusCode, "文件上传应该成功")

		var result map[string]interface{}
		err = json.NewDecoder(uploadResp.Body).Decode(&result)
		require.NoError(t, err, "解析上传响应失败")

		assert.Equal(t, float64(0), result["err_no"], "上传错误码应该为0")
		assert.NotNil(t, result["data"], "应该返回上传文件路径")

		uploadedPath := result["data"].(string)
		t.Logf("文件上传成功，路径: %s", uploadedPath)

		// 验证文件是否真的上传了
		fullPath := filepath.Join("../", uploadedPath)
		_, err = os.Stat(fullPath)
		assert.NoError(t, err, "上传的文件应该存在")
	})

	t.Run("文件下载测试", func(t *testing.T) {
		// 首先上传一个文件
		testFileName := "test_download_file.txt"
		testContent := "这是用于下载测试的文件内容。"

		err := os.WriteFile(testFileName, []byte(testContent), 0644)
		require.NoError(t, err, "创建测试文件失败")
		defer os.Remove(testFileName)

		// 创建认证头
		headers, err := createAuthHeaders(testDevices[0])
		require.NoError(t, err, "创建认证头失败")

		// 上传文件
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)

		file, err := os.Open(testFileName)
		require.NoError(t, err, "打开测试文件失败")
		defer file.Close()

		part, err := writer.CreateFormFile("file", testFileName)
		require.NoError(t, err, "创建表单文件字段失败")

		_, err = io.Copy(part, file)
		require.NoError(t, err, "复制文件内容失败")

		err = writer.Close()
		require.NoError(t, err, "关闭writer失败")

		// 发送上传请求
		req, err := http.NewRequest("POST", testServer.URL+"/customer/upload/file", &buf)
		require.NoError(t, err, "创建上传请求失败")

		req.Header.Set("Content-Type", writer.FormDataContentType())
		for key, value := range headers {
			req.Header.Set(key, value)
		}

		client := &http.Client{}
		uploadResp, err := client.Do(req)
		require.NoError(t, err, "发送上传请求失败")
		uploadResp.Body.Close()
		require.Equal(t, http.StatusOK, uploadResp.StatusCode, "文件上传应该成功")

		// 现在测试下载
		downloadReq, err := http.NewRequest("GET", testServer.URL+"/customer/download/file/"+testFileName, nil)
		require.NoError(t, err, "创建下载请求失败")

		for key, value := range headers {
			downloadReq.Header.Set(key, value)
		}

		downloadResp, err := client.Do(downloadReq)
		require.NoError(t, err, "发送下载请求失败")
		defer downloadResp.Body.Close()

		assert.Equal(t, http.StatusOK, downloadResp.StatusCode, "文件下载应该成功")

		// 验证下载的文件内容
		downloadedContent, err := io.ReadAll(downloadResp.Body)
		require.NoError(t, err, "读取下载内容失败")

		assert.Equal(t, testContent, string(downloadedContent), "下载的文件内容应该与原文件一致")

		t.Logf("文件下载测试成功，文件大小: %d bytes", len(downloadedContent))
	})

	t.Run("并发文件上传测试", func(t *testing.T) {
		var wg sync.WaitGroup
		uploadCount := 5
		results := make(chan bool, uploadCount)

		for i := 0; i < uploadCount; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()

				// 创建测试文件
				testFileName := fmt.Sprintf("concurrent_test_%d.txt", index)
				testContent := fmt.Sprintf("并发测试文件 %d 的内容", index)

				err := os.WriteFile(testFileName, []byte(testContent), 0644)
				if err != nil {
					t.Errorf("创建测试文件失败: %v", err)
					results <- false
					return
				}
				defer os.Remove(testFileName)

				// 创建认证头
				headers, err := createAuthHeaders(testDevices[0])
				if err != nil {
					t.Errorf("创建认证头失败: %v", err)
					results <- false
					return
				}

				// 创建multipart表单
				var buf bytes.Buffer
				writer := multipart.NewWriter(&buf)

				file, err := os.Open(testFileName)
				if err != nil {
					t.Errorf("打开测试文件失败: %v", err)
					results <- false
					return
				}
				defer file.Close()

				part, err := writer.CreateFormFile("file", testFileName)
				if err != nil {
					t.Errorf("创建表单文件字段失败: %v", err)
					results <- false
					return
				}

				_, err = io.Copy(part, file)
				if err != nil {
					t.Errorf("复制文件内容失败: %v", err)
					results <- false
					return
				}

				err = writer.Close()
				if err != nil {
					t.Errorf("关闭writer失败: %v", err)
					results <- false
					return
				}

				// 发送上传请求
				req, err := http.NewRequest("POST", testServer.URL+"/customer/upload/file", &buf)
				if err != nil {
					t.Errorf("创建上传请求失败: %v", err)
					results <- false
					return
				}

				req.Header.Set("Content-Type", writer.FormDataContentType())
				for key, value := range headers {
					req.Header.Set(key, value)
				}

				client := &http.Client{}
				uploadResp, err := client.Do(req)
				if err != nil {
					t.Errorf("发送上传请求失败: %v", err)
					results <- false
					return
				}
				defer uploadResp.Body.Close()

				success := uploadResp.StatusCode == http.StatusOK
				results <- success

				if success {
					t.Logf("并发上传 %d 成功", index)
				} else {
					t.Errorf("并发上传 %d 失败，状态码: %d", index, uploadResp.StatusCode)
				}
			}(i)
		}

		wg.Wait()
		close(results)

		successCount := 0
		for result := range results {
			if result {
				successCount++
			}
		}

		assert.Equal(t, uploadCount, successCount, "所有并发上传都应该成功")
		t.Logf("并发文件上传测试完成: %d/%d 成功", successCount, uploadCount)
	})

	t.Run("指令传输测试", func(t *testing.T) {
		// 创建认证头
		headers, err := createAuthHeaders(testDevices[0])
		require.NoError(t, err, "创建认证头失败")

		// 测试基本指令
		commandData := map[string]interface{}{
			"command": "status",
			"args":    "",
		}

		resp := sendRequest(t, "POST", "/customer/command/execute", commandData, headers)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "指令执行应该成功")

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err, "解析指令响应失败")

		assert.Equal(t, float64(0), result["err_no"], "指令错误码应该为0")
		assert.NotNil(t, result["data"], "应该返回指令执行结果")

		t.Logf("指令执行成功，结果: %s", result["data"])

		// 测试带参数的指令
		commandWithArgs := map[string]interface{}{
			"command": "restart",
			"args":    "--force",
		}

		resp2 := sendRequest(t, "POST", "/customer/command/execute", commandWithArgs, headers)
		defer resp2.Body.Close()

		assert.Equal(t, http.StatusOK, resp2.StatusCode, "带参数的指令执行应该成功")

		var result2 map[string]interface{}
		err = json.NewDecoder(resp2.Body).Decode(&result2)
		require.NoError(t, err, "解析指令响应失败")

		assert.Equal(t, float64(0), result2["err_no"], "指令错误码应该为0")
		t.Logf("带参数指令执行成功，结果: %s", result2["data"])
	})
}

// Test04_DeviceManagement 测试设备管理功能
func Test04_DeviceManagement(t *testing.T) {
	setupTestEnvironment(t)
	defer teardownTestEnvironment(t)

	// 注册测试设备
	deviceData := map[string]interface{}{
		"device_id": testDevices[0],
		"title":     "设备管理测试设备",
		"enabled":   true,
	}

	resp := sendRequest(t, "POST", "/customer/auth/add", deviceData, nil)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "设备注册失败")

	t.Run("获取设备列表", func(t *testing.T) {
		headers, err := createAuthHeaders(testDevices[0])
		require.NoError(t, err, "创建认证头失败")

		resp := sendRequest(t, "GET", "/customer/device/", nil, headers)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "获取设备列表应该成功")

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err, "解析响应失败")

		assert.Equal(t, float64(0), result["err_no"], "错误码应该为0")
		assert.NotNil(t, result["data"], "应该返回设备列表")

		devices := result["data"].([]interface{})
		assert.Greater(t, len(devices), 0, "设备列表不应该为空")

		t.Logf("获取到 %d 个设备", len(devices))
	})

	t.Run("更新设备状态", func(t *testing.T) {
		headers, err := createAuthHeaders(testDevices[0])
		require.NoError(t, err, "创建认证头失败")

		updateData := map[string]interface{}{
			"device_id": testDevices[0],
			"enabled":   false,
		}

		resp := sendRequest(t, "PUT", "/customer/device/", updateData, headers)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "更新设备状态应该成功")

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err, "解析响应失败")

		assert.Equal(t, float64(0), result["err_no"], "错误码应该为0")

		t.Log("设备状态更新成功")
	})
}

// Test05_AuthenticationSecurity 测试认证安全性
func Test05_AuthenticationSecurity(t *testing.T) {
	setupTestEnvironment(t)
	defer teardownTestEnvironment(t)

	// 注册测试设备
	deviceData := map[string]interface{}{
		"device_id": testDevices[0],
		"title":     "认证安全测试设备",
		"enabled":   true,
	}

	resp := sendRequest(t, "POST", "/customer/auth/add", deviceData, nil)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "设备注册失败")

	t.Run("无认证头访问", func(t *testing.T) {
		resp := sendRequest(t, "GET", "/customer/device/", nil, nil)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode, "无认证头应该返回400")
		t.Log("无认证头访问被正确拒绝")
	})

	t.Run("错误的设备ID", func(t *testing.T) {
		headers, err := createAuthHeaders("non_existent_device")
		require.NoError(t, err, "创建认证头失败")

		resp := sendRequest(t, "GET", "/customer/device/", nil, headers)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "错误的设备ID应该返回403")
		t.Log("错误的设备ID被正确拒绝")
	})

	t.Run("过期的时间戳", func(t *testing.T) {
		token := &auth.DeviceToken{
			ID:        testDevices[0],
			Timestamp: time.Now().Unix() - 300, // 5分钟前
		}

		err := token.GenerateSignature(publicKey)
		require.NoError(t, err, "生成签名失败")

		headers := map[string]string{
			"LY-Device-ID": token.ID,
			"LY-Timestamp": strconv.FormatInt(token.Timestamp, 10),
			"LY-Signature": token.Signature,
		}

		resp := sendRequest(t, "GET", "/customer/device/", nil, headers)
		defer resp.Body.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "过期的时间戳应该返回403")
		t.Log("过期的时间戳被正确拒绝")
	})
}

// Test06_PerformanceStress 测试性能和压力
func Test06_PerformanceStress(t *testing.T) {
	setupTestEnvironment(t)
	defer teardownTestEnvironment(t)

	// 注册测试设备
	for i := 0; i < 3; i++ {
		deviceData := map[string]interface{}{
			"device_id": testDevices[i],
			"title":     fmt.Sprintf("性能测试设备%03d", i+1),
			"enabled":   true,
		}

		resp := sendRequest(t, "POST", "/customer/auth/add", deviceData, nil)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "设备注册失败")
	}

	t.Run("高并发请求测试", func(t *testing.T) {
		concurrency := 50
		requestsPerDevice := 20

		var wg sync.WaitGroup
		results := make(chan time.Duration, concurrency*requestsPerDevice)

		startTime := time.Now()

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()

				deviceID := testDevices[goroutineID%3] // 轮询使用设备

				for j := 0; j < requestsPerDevice; j++ {
					requestStart := time.Now()

					headers, err := createAuthHeaders(deviceID)
					if err != nil {
						t.Errorf("创建认证头失败: %v", err)
						continue
					}

					resp := sendRequest(t, "GET", "/customer/device/", nil, headers)
					resp.Body.Close()

					requestDuration := time.Since(requestStart)
					results <- requestDuration

					if resp.StatusCode != http.StatusOK {
						t.Errorf("请求失败，状态码: %d", resp.StatusCode)
					}
				}
			}(i)
		}

		wg.Wait()
		close(results)

		totalDuration := time.Since(startTime)

		var totalRequestTime time.Duration
		requestCount := 0
		var minTime, maxTime time.Duration

		for duration := range results {
			if requestCount == 0 {
				minTime = duration
				maxTime = duration
			} else {
				if duration < minTime {
					minTime = duration
				}
				if duration > maxTime {
					maxTime = duration
				}
			}
			totalRequestTime += duration
			requestCount++
		}

		avgRequestTime := totalRequestTime / time.Duration(requestCount)
		qps := float64(requestCount) / totalDuration.Seconds()

		t.Logf("性能测试结果:")
		t.Logf("  总请求数: %d", requestCount)
		t.Logf("  总耗时: %v", totalDuration)
		t.Logf("  平均响应时间: %v", avgRequestTime)
		t.Logf("  最小响应时间: %v", minTime)
		t.Logf("  最大响应时间: %v", maxTime)
		t.Logf("  QPS: %.2f", qps)

		// 性能断言
		assert.Less(t, avgRequestTime, 100*time.Millisecond, "平均响应时间应该小于100ms")
		assert.Greater(t, qps, 100.0, "QPS应该大于100")
	})
}

// Test07_ManagementPage 测试管理页面功能
func Test07_ManagementPage(t *testing.T) {
	setupTestEnvironment(t)
	defer teardownTestEnvironment(t)

	// 注册几个测试设备
	for i, deviceID := range testDevices {
		deviceData := map[string]interface{}{
			"device_id": deviceID,
			"title":     fmt.Sprintf("管理页面测试设备_%d", i+1),
			"enabled":   i%2 == 0, // 交替启用/禁用
		}

		resp := sendRequest(t, "POST", "/customer/auth/add", deviceData, nil)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "设备注册失败")
	}

	t.Run("管理页面访问测试", func(t *testing.T) {
		// 测试管理页面是否可以访问
		req, err := http.NewRequest("GET", testServer.URL+"/customer/management", nil)
		require.NoError(t, err, "创建管理页面请求失败")

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err, "访问管理页面失败")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "管理页面应该可以访问")
		assert.Equal(t, "text/html; charset=utf-8", resp.Header.Get("Content-Type"), "应该返回HTML内容")

		// 读取页面内容
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "读取管理页面内容失败")

		bodyStr := string(body)
		assert.Contains(t, bodyStr, "客户端管理系统", "页面应该包含标题")
		assert.Contains(t, bodyStr, "设备列表", "页面应该包含设备列表")
		assert.Contains(t, bodyStr, "刷新数据", "页面应该包含刷新按钮")

		t.Logf("管理页面访问成功，页面大小: %d bytes", len(body))
	})

	t.Run("设备状态API测试", func(t *testing.T) {
		// 测试设备列表API（管理页面会调用这个API）
		req, err := http.NewRequest("GET", testServer.URL+"/customer/device/", nil)
		require.NoError(t, err, "创建设备列表请求失败")

		// 使用第一个设备的认证头
		headers, err := createAuthHeaders(testDevices[0])
		require.NoError(t, err, "创建认证头失败")

		for key, value := range headers {
			req.Header.Set(key, value)
		}

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err, "获取设备列表失败")
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "设备列表API应该成功")

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err, "解析设备列表响应失败")

		assert.Equal(t, float64(0), result["err_no"], "错误码应该为0")
		assert.NotNil(t, result["data"], "应该返回设备数据")

		devices := result["data"].([]interface{})
		assert.GreaterOrEqual(t, len(devices), 3, "应该至少有3个设备")

		// 验证设备数据结构
		if len(devices) > 0 {
			device := devices[0].(map[string]interface{})
			assert.Contains(t, device, "device_id", "设备数据应该包含device_id")
			assert.Contains(t, device, "title", "设备数据应该包含title")
			assert.Contains(t, device, "enabled", "设备数据应该包含enabled")
			assert.Contains(t, device, "created_at", "设备数据应该包含created_at")
			assert.Contains(t, device, "updated_at", "设备数据应该包含updated_at")
		}

		t.Logf("设备状态API测试成功，返回 %d 个设备", len(devices))
	})
}
