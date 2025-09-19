#!/usr/bin/env python3
"""
带认证功能的文件上传测试客户端
"""
import requests
import os
import time
import base64
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor, as_completed

# 服务器配置
SERVER_URL = "http://localhost:8080"
UPLOAD_ENDPOINT = "/customer/upload/file"
PUBLIC_KEY_PATH = "public_key.pem"

class DeviceTokenGenerator:
    """设备token生成器"""
    
    def __init__(self, public_key_path):
        """初始化，加载公钥"""
        with open(public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
    
    def pack_payload(self, device_id, timestamp):
        """打包payload，按Go代码逻辑排序"""
        fields = [device_id, str(timestamp)]
        fields.sort()  # 按字母顺序排序
        return "|".join(fields)
    
    def encrypt_payload(self, payload):
        """使用公钥加密payload"""
        try:
            encrypted_data = self.public_key.encrypt(
                payload.encode('utf-8'),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return encrypted_data
        except Exception as e:
            print(f"加密payload失败: {e}")
            raise
    
    def generate_signature(self, device_id, timestamp):
        """生成签名"""
        try:
            # 1. 打包payload
            payload = self.pack_payload(device_id, timestamp)
            print(f"Payload: {payload}")
            
            # 2. 加密payload
            encrypted_data = self.encrypt_payload(payload)
            
            # 3. 计算SHA256哈希
            hash_value = hashlib.sha256(encrypted_data).digest()
            
            # 4. 用公钥加密哈希值
            encrypted_hash = self.public_key.encrypt(
                hash_value,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # 5. Base64编码
            signature = base64.b64encode(encrypted_hash).decode('utf-8')
            
            return signature
        except Exception as e:
            print(f"生成签名失败: {e}")
            raise
    
    def generate_headers(self, device_id):
        """生成认证头"""
        timestamp = int(time.time())
        signature = self.generate_signature(device_id, timestamp)
        
        return {
            'LY-Device-ID': device_id,
            'LY-Timestamp': str(timestamp),
            'LY-Signature': signature
        }

def create_test_file(filename, size_mb=1):
    """创建测试文件"""
    with open(filename, 'wb') as f:
        f.write(b'A' * (size_mb * 1024 * 1024))
    print(f"创建测试文件: {filename} ({size_mb}MB)")

def upload_file_with_auth(file_path, device_id="test_device_001", token_generator=None):
    """带认证的文件上传"""
    url = f"{SERVER_URL}{UPLOAD_ENDPOINT}"
    
    try:
        # 生成认证头
        auth_headers = token_generator.generate_headers(device_id)
        print(f"认证头: {auth_headers}")
        
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'application/octet-stream')}
            data = {'device_id': device_id}
            
            start_time = time.time()
            response = requests.post(
                url, 
                files=files, 
                data=data, 
                headers=auth_headers,
                timeout=30
            )
            end_time = time.time()
            
            upload_time = end_time - start_time
            file_size = os.path.getsize(file_path)
            speed = file_size / upload_time / 1024 / 1024  # MB/s
            
            return {
                'success': response.status_code == 200,
                'status_code': response.status_code,
                'response_text': response.text,
                'upload_time': upload_time,
                'file_size': file_size,
                'speed_mbps': speed,
                'device_id': device_id
            }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'device_id': device_id
        }

def test_auth_upload():
    """测试带认证的文件上传"""
    print("\n=== 测试带认证的文件上传 ===")
    
    try:
        # 初始化token生成器
        token_generator = DeviceTokenGenerator(PUBLIC_KEY_PATH)
        print("✅ 公钥加载成功")
        
        # 创建测试文件
        test_file = "test_auth_file_1mb.bin"
        create_test_file(test_file, 1)
        
        try:
            result = upload_file_with_auth(test_file, "test_device_001", token_generator)
            
            if result['success']:
                print(f"✅ 认证上传成功!")
                print(f"   文件大小: {result['file_size']/1024/1024:.2f}MB")
                print(f"   上传时间: {result['upload_time']:.2f}秒")
                print(f"   上传速度: {result['speed_mbps']:.2f}MB/s")
                print(f"   响应: {result['response_text']}")
            else:
                print(f"❌ 认证上传失败!")
                print(f"   状态码: {result.get('status_code', 'N/A')}")
                print(f"   响应: {result.get('response_text', result.get('error', 'Unknown error'))}")
        
        finally:
            # 清理测试文件
            if os.path.exists(test_file):
                os.remove(test_file)
                
    except Exception as e:
        print(f"❌ 测试失败: {e}")

def test_concurrent_auth_upload(num_threads=3, file_size_mb=1):
    """测试并发认证上传"""
    print(f"\n=== 测试并发认证上传 ({num_threads}个线程) ===")
    
    try:
        # 初始化token生成器
        token_generator = DeviceTokenGenerator(PUBLIC_KEY_PATH)
        
        # 创建测试文件
        test_files = []
        for i in range(num_threads):
            filename = f"test_auth_file_{i}_{file_size_mb}mb.bin"
            create_test_file(filename, file_size_mb)
            test_files.append(filename)
        
        try:
            start_time = time.time()
            
            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                # 提交所有上传任务
                future_to_file = {
                    executor.submit(
                        upload_file_with_auth, 
                        file_path, 
                        f"auth_device_{i:03d}", 
                        token_generator
                    ): file_path 
                    for i, file_path in enumerate(test_files)
                }
                
                results = []
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        result = future.result()
                        result['file_path'] = file_path
                        results.append(result)
                    except Exception as exc:
                        print(f"文件 {file_path} 上传异常: {exc}")
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # 统计结果
            successful_uploads = [r for r in results if r['success']]
            failed_uploads = [r for r in results if not r['success']]
            
            print(f"\n📊 并发认证上传结果:")
            print(f"   总时间: {total_time:.2f}秒")
            print(f"   成功上传: {len(successful_uploads)}/{len(results)}")
            print(f"   失败上传: {len(failed_uploads)}")
            
            if successful_uploads:
                total_size = sum(r['file_size'] for r in successful_uploads)
                avg_speed = total_size / total_time / 1024 / 1024
                print(f"   总数据量: {total_size/1024/1024:.2f}MB")
                print(f"   平均速度: {avg_speed:.2f}MB/s")
                
                individual_speeds = [r['speed_mbps'] for r in successful_uploads]
                print(f"   单个文件平均速度: {sum(individual_speeds)/len(individual_speeds):.2f}MB/s")
            
            if failed_uploads:
                print(f"\n❌ 失败的上传:")
                for result in failed_uploads:
                    print(f"   {result['file_path']}: {result.get('error', result.get('response_text', 'Unknown error'))}")
        
        finally:
            # 清理测试文件
            for file_path in test_files:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    
    except Exception as e:
        print(f"❌ 并发测试失败: {e}")

def test_token_generation():
    """测试token生成"""
    print("\n=== 测试Token生成 ===")
    
    try:
        token_generator = DeviceTokenGenerator(PUBLIC_KEY_PATH)
        
        device_id = "test_device_123"
        headers = token_generator.generate_headers(device_id)
        
        print(f"✅ Token生成成功:")
        print(f"   Device ID: {headers['LY-Device-ID']}")
        print(f"   Timestamp: {headers['LY-Timestamp']}")
        print(f"   Signature: {headers['LY-Signature'][:50]}...")
        
        return True
        
    except Exception as e:
        print(f"❌ Token生成失败: {e}")
        return False

def main():
    """主测试函数"""
    print("🚀 开始带认证的文件上传测试")
    
    # 检查公钥文件
    if not os.path.exists(PUBLIC_KEY_PATH):
        print(f"❌ 公钥文件不存在: {PUBLIC_KEY_PATH}")
        return
    
    # 测试token生成
    if not test_token_generation():
        print("❌ Token生成测试失败，退出")
        return
    
    # 测试单个认证上传
    test_auth_upload()
    
    # 测试并发认证上传
    test_concurrent_auth_upload(num_threads=3, file_size_mb=1)
    test_concurrent_auth_upload(num_threads=5, file_size_mb=2)
    
    print("\n🎉 认证测试完成!")

if __name__ == "__main__":
    main()