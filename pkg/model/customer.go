package model

import (
	"fmt"

	"gorm.io/gorm"
)

func UpdateEnabledByDeviceID(db *gorm.DB, deviceID string, enabled bool) error {
	result := db.Model(&Customer{}).Where("device_id = ?", deviceID).Update("enabled", enabled)
	if result.Error != nil {
		return fmt.Errorf("更新设备%s的enabled状态失败: %w", deviceID, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("未找到设备ID为%s的记录", deviceID)
	}
	return nil
}

func GetCustomerByDeviceID(db *gorm.DB, deviceID string) (*Customer, error) {
	var customer Customer
	err := db.Where("device_id = ?", deviceID).First(&customer).Error
	if err != nil {
		return nil, fmt.Errorf("查询设备ID为%s的客户失败: %w", deviceID, err)
	}
	return &customer, nil
}

func GetEnabledDeviceIDs(db *gorm.DB) ([]string, error) {
	var deviceIDs []string
	err := db.Model(&Customer{}).Where("enabled = ?", true).Pluck("device_id", &deviceIDs).Error
	if err != nil {
		return nil, fmt.Errorf("查询启用设备ID失败: %w", err)
	}
	return deviceIDs, nil
}

func CreateTestDataAndGetDeviceIDs(db *gorm.DB) ([]string, error) {
	// 检查表是否为空
	var count int64
	if err := db.Model(&Customer{}).Count(&count).Error; err != nil {
		return nil, fmt.Errorf("检查表数据失败: %v", err)
	}

	// 如果表不为空，直接返回现有的可用设备ID
	if count > 0 {
		return GetEnabledDeviceIDs(db)
	}

	// 表为空，创建10条测试数据
	testCustomers := []Customer{
		{DeviceID: "test-device-001", Enabled: true, Title: "测试设备001"},
		{DeviceID: "test-device-002", Enabled: true, Title: "测试设备002"},
		{DeviceID: "test-device-003", Enabled: true, Title: "测试设备003"},
		{DeviceID: "test-device-004", Enabled: true, Title: "测试设备004"},
		{DeviceID: "test-device-005", Enabled: true, Title: "测试设备005"},
		{DeviceID: "test-device-006", Enabled: false, Title: "测试设备006"},
		{DeviceID: "test-device-007", Enabled: true, Title: "测试设备007"},
		{DeviceID: "test-device-008", Enabled: true, Title: "测试设备008"},
		{DeviceID: "test-device-009", Enabled: false, Title: "测试设备009"},
		{DeviceID: "test-device-010", Enabled: true, Title: "测试设备010"},
	}

	// 批量插入测试数据
	if err := db.Create(&testCustomers).Error; err != nil {
		return nil, fmt.Errorf("创建测试数据失败: %v", err)
	}

	// 返回所有enabled=1的设备ID
	return GetEnabledDeviceIDs(db)
}
