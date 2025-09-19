package api

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/luoying/gin-hander/conf"
	"github.com/luoying/gin-hander/pkg/auth"
	"github.com/luoying/gin-hander/pkg/log"
	"github.com/luoying/gin-hander/pkg/model"
	"github.com/luoying/gin-hander/pkg/rsautils"
	"github.com/luoying/gin-hander/pkg/utils"
	"github.com/pkg/errors"
	"gorm.io/gorm"
)

type CustomerconstManager struct {
	cfg *conf.Config
}

func NewCustomerManager(cfg *conf.Config) (*CustomerconstManager, error) {
	logger := log.GetLogger("Customer")
	logger.Info("create new Customer manager")
	return &CustomerconstManager{cfg: cfg}, nil
}

func (manager *CustomerconstManager) Create(device_id, titile string, enable bool) error {
	customer, err := model.GetCustomerByDeviceID(manager.cfg.DB(), device_id)
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return errors.Wrap(err, fmt.Sprintf("查询设备ID为%s的客户失败", device_id))
		}
	}
	if customer != nil {
		return errors.New(fmt.Sprintf("设备ID为%s的客户已存在", device_id))
	}
	customer = &model.Customer{
		DeviceID: device_id,
		Title:    titile,
		Enabled:  enable,
	}
	return manager.cfg.DB().Create(customer).Error
}

func (manager *CustomerconstManager) Update(device_id string, enabled bool) error {
	return model.UpdateEnabledByDeviceID(manager.cfg.DB(), device_id, enabled)
}

func (manager *CustomerconstManager) Get(device_id string) (*model.Customer, error) {
	return model.GetCustomerByDeviceID(manager.cfg.DB(), device_id)
}

func (manager *CustomerconstManager) GetEnabledDeviceIDs() ([]string, error) {
	return model.GetEnabledDeviceIDs(manager.cfg.DB())
}

type createCustomerService struct {
	DeviceID string `json:"device_id" binding:"required"`
	Title    string `json:"title" binding:"required"`
	Enabled  bool   `json:"enabled" binding:"required"`
}

func (ccs createCustomerService) Invoke(worker *CustomerWorker, c *gin.Context) (*model.Customer, error) {
	err := c.ShouldBindBodyWithJSON(&ccs)
	if err != nil {
		return nil, err
	}
	if err := worker.manager.Create(ccs.DeviceID, ccs.Title, ccs.Enabled); err != nil {
		return nil, err
	}
	return worker.manager.Get(ccs.DeviceID)
}

type updateCustomerService struct {
	DeviceID string `json:"device_id" binding:"required"`
	Enabled  bool   `json:"enabled"`
}

func (ucs updateCustomerService) Invoke(worker *CustomerWorker, c *gin.Context) (*model.Customer, error) {
	var request updateCustomerService
	err := c.ShouldBindBodyWithJSON(&request)
	if err != nil {
		return nil, err
	}
	if err := worker.manager.Update(request.DeviceID, request.Enabled); err != nil {
		return nil, err
	}
	return worker.manager.Get(request.DeviceID)
}

type getAllCustomerService struct {
}

func (gcs getAllCustomerService) Invoke(worker *CustomerWorker, c *gin.Context) ([]*model.Customer, error) {
	// 获取启用的设备ID列表
	deviceIDs, err := worker.manager.GetEnabledDeviceIDs()
	if err != nil {
		return nil, err
	}

	// 根据设备ID列表获取对应的客户信息
	var customers []*model.Customer
	for _, deviceID := range deviceIDs {
		customer, err := worker.manager.Get(deviceID)
		if err != nil {
			return nil, err
		}
		if customer != nil {
			customers = append(customers, customer)
		}
	}
	return customers, nil
}

// 文件上传服务
type fileUploadService struct {
	FileName string `form:"filename"` // 自定义文件名（可选）

}

// 文件下载服务
type fileDownloadService struct {
	FileName string `uri:"filename" binding:"required"`
}

func (fds fileDownloadService) Invoke(worker *CustomerWorker, c *gin.Context) (*string, error) {
	// 构建文件路径
	filePath := filepath.Join(worker.cfg.UploadPath, fds.FileName)
	
	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, errors.New("文件不存在")
	}
	
	// 设置响应头
	c.Header("Content-Description", "File Transfer")
	c.Header("Content-Transfer-Encoding", "binary")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fds.FileName))
	c.Header("Content-Type", "application/octet-stream")
	
	// 发送文件
	c.File(filePath)
	
	logMsg := fmt.Sprintf("文件下载: %s", fds.FileName)
	worker.logger.Info(logMsg)
	
	return &filePath, nil
}

// 指令传输服务
type commandService struct {
	Command string `json:"command" binding:"required"`
	Args    string `json:"args"`
}

func (cs commandService) Invoke(worker *CustomerWorker, c *gin.Context) (*string, error) {
	// 获取当前设备信息
	device, exists := c.Get("current_device")
	if !exists {
		return nil, errors.New("设备信息不存在")
	}
	
	deviceInfo := device.(*model.Customer)
	
	// 记录指令
	logMsg := fmt.Sprintf("设备 %s 执行指令: %s %s", deviceInfo.DeviceID, cs.Command, cs.Args)
	worker.logger.Info(logMsg)
	
	// 这里可以根据需要实现具体的指令处理逻辑
	// 目前只是简单返回确认信息
	result := fmt.Sprintf("指令已接收: %s %s", cs.Command, cs.Args)
	
	return &result, nil
}

type Sign struct {
	DeviceID string `uri:"device_id" binding:"required"`
}

func (s Sign) Invoke(worker *CustomerWorker, c *gin.Context) (*string, error) {
	return nil, nil
}

func (fus fileUploadService) Invoke(worker *CustomerWorker, c *gin.Context) (*string, error) {
	// 生产这里只要改成调用mino 之类的即可
	// 绑定表单参数
	if err := c.ShouldBind(&fus); err != nil {
		return nil, errors.Wrap(err, "绑定表单参数失败")
	}

	// 设置最大上传文件大小为 32MB
	c.Request.ParseMultipartForm(32 << 20)

	// 获取上传的文件
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		return nil, errors.Wrap(err, "获取上传文件失败")
	}
	defer file.Close()

	// 获取配置的上传目录
	uploadDir := worker.cfg.UploadPath

	// 确定最终文件名
	var finalFileName string
	if fus.FileName != "" {
		// 使用自定义文件名，保留原始扩展名
		ext := filepath.Ext(header.Filename)
		finalFileName = fus.FileName + ext
	} else {
		// 使用原始文件名，添加时间戳避免冲突
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		ext := filepath.Ext(header.Filename)
		baseFilename := header.Filename[:len(header.Filename)-len(ext)]
		finalFileName = fmt.Sprintf("%s_%s%s", baseFilename, timestamp, ext)
	}

	filePath := filepath.Join(uploadDir, finalFileName)
	dst, err := os.Create(filePath)
	if err != nil {
		return nil, errors.Wrap(err, "创建目标文件失败")
	}
	defer dst.Close()

	// 复制文件内容
	fileSize, err := io.Copy(dst, file)
	if err != nil {
		return nil, errors.Wrap(err, "保存文件失败")
	}

	logMsg := fmt.Sprintf("文件上传成功: %s, 大小: %d bytes", finalFileName, fileSize)
	worker.logger.Info(logMsg)
	// 返回文件路径
	return &filePath, nil
}

type CustomerWorker struct {
	manager   *CustomerconstManager
	validator auth.DeviceValidator
	cfg       *conf.Config
	logger    log.Logger
}

func (worker *CustomerWorker) Tag() string {
	return "customer"
}

func (p *CustomerWorker) Serve(_ context.Context) error {
	return nil
}

func NewCustomerWorker(cfg *conf.Config) (utils.APIWorker, error) {
	manager, err := NewCustomerManager(cfg)
	if err != nil {
		return nil, err
	}

	// 加载RSA私钥用于设备验证
	privateKey, err := rsautils.LoadPrivateKey("private_key.pem")
	if err != nil {
		return nil, errors.Wrap(err, "failed to load private key")
	}

	// 创建设备验证器
	validator := auth.DBDeviceValidator(cfg.DB(), privateKey)

	return &CustomerWorker{
		manager:   manager,
		validator: validator,
		cfg:       cfg,
		logger:    log.GetLogger("CustomerWorker"),
	}, nil
}
func (worker *CustomerWorker) Mount(r gin.IRouter) {
	// 静态文件服务
	r.Static("/static", "./static")
	
	// 管理页面路由
	r.GET("/management", func(c *gin.Context) {
		c.File("./static/management.html")
	})

	authApi := r.Group("/auth")
	authApi.POST("/add", utils.InvokeApiService[*CustomerWorker, *model.Customer, createCustomerService](worker))

	deviceAPI := r.Group("/device")
	deviceAPI.Use(
		auth.CurrentDeviceMiddleware(worker.validator),
	)

	deviceAPI.PUT("/", utils.InvokeApiService[*CustomerWorker, *model.Customer, updateCustomerService](worker))
	deviceAPI.GET("/", utils.InvokeApiService[*CustomerWorker, []*model.Customer, getAllCustomerService](worker))

	// 文件上传路由
	uploadAPI := r.Group("/upload")
	uploadAPI.Use(
		auth.CurrentDeviceMiddleware(worker.validator),
	)
	uploadAPI.POST("/file", utils.InvokeApiService[*CustomerWorker, *string, fileUploadService](worker))

	// 文件下载路由
	downloadAPI := r.Group("/download")
	downloadAPI.Use(
		auth.CurrentDeviceMiddleware(worker.validator),
	)
	downloadAPI.GET("/file/:filename", utils.InvokeApiService[*CustomerWorker, *string, fileDownloadService](worker))

	// 指令传输路由
	commandAPI := r.Group("/command")
	commandAPI.Use(
		auth.CurrentDeviceMiddleware(worker.validator),
	)
	commandAPI.POST("/execute", utils.InvokeApiService[*CustomerWorker, *string, commandService](worker))
}
